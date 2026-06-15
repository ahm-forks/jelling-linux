/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2015  Nathaniel McCallum, Red Hat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>


#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <linux/uinput.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#define MAN_PATH "/"
#define ADV_PATH "/adv"
#define SVC_PATH "/svc"
#define CHR_PATH "/svc/chr"
#define SVC_UUID "B670003C-0079-465C-9BA7-6C0539CCD67F"
#define CHR_UUID "F4186B06-D796-4327-AF39-AC22C50BDCA8"

#define CHR_FLAGS "secure-write"
#define CHR_NFLAG 1

#define PROP(name, sig, func) \
    SD_BUS_PROPERTY(name, sig, func, 0, SD_BUS_VTABLE_PROPERTY_CONST)

#define METH(name, sig, rsig, func) \
    SD_BUS_METHOD(name, sig, rsig, func, SD_BUS_VTABLE_UNPRIVILEGED)

#define MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesAdded'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define COUNT(array) (sizeof(array) / sizeof(*array))

#define SCOPED(type) \
    __attribute__((cleanup(type ## _cleanup))) type

#if ENABLE_DEBUG
#define DEBUG(format, ...) LOG(DEBUG, format, ## __VA_ARGS__)
#else
#define DEBUG(format, ...)
#endif

#define INFO(format, ...)  LOG(INFO,  format, ## __VA_ARGS__)
#define WARN(format, ...)  LOG(WARN,  format, ## __VA_ARGS__)
#define ERROR(format, ...) LOG(ERROR, format, ## __VA_ARGS__)
#define ABORT(ERRNUM, format, ...) do { \
    LOG(FATAL, format ": %s", ## __VA_ARGS__, strerror(ERRNUM));\
    exit(EXIT_FAILURE);\
} while(0)

typedef enum {
    DEBUG = 0,
    INFO  = 5,
    WARN  = 10,
    ERROR = 15,
    FATAL = 20,
} LogLevel;

typedef int uinput;

static const char *strloglvl(LogLevel lvl)
{
    if (lvl >= FATAL) return "FATAL";
    if (lvl >= ERROR) return "ERROR";
    if (lvl >= WARN)  return "WARN";
    if (lvl >= INFO)  return "INFO";
    if (lvl >= DEBUG) return "DEBUG";
    return "UNKNOWN";
}

static void LOG(LogLevel level, const char *fmt, ...)
{
    va_list ap;
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);

    fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d [%s] ",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            strloglvl(level));

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
    fflush(stderr);
}

static void
uinput_cleanup(uinput *i)
{
    if (i == NULL || *i < 0)
        return;

    ioctl(*i, UI_DEV_DESTROY);
    close(*i);
}

static void
sd_event_cleanup(sd_event **loop)
{
    if (loop == NULL || *loop == NULL)
        return;

    sd_event_unref(*loop);
}

static void
sd_bus_message_cleanup(sd_bus_message **msg)
{
    if (msg == NULL || *msg == NULL)
        return;

    sd_bus_message_unref(*msg);
}

static void
sd_bus_cleanup(sd_bus **bus)
{
    if (bus == NULL || *bus == NULL)
        return;

    sd_bus_unref(*bus);
}

static inline uint16_t
char2key(uint8_t c)
{
    switch (c) {
    case '0':
        return KEY_0;
    case '1':
        return KEY_1;
    case '2':
        return KEY_2;
    case '3':
        return KEY_3;
    case '4':
        return KEY_4;
    case '5':
        return KEY_5;
    case '6':
        return KEY_6;
    case '7':
        return KEY_7;
    case '8':
        return KEY_8;
    case '9':
        return KEY_9;
    default:
        return KEY_UNKNOWN;
    }
}

static int
adv_props(sd_bus *bus, const char *path, const char *interface,
          const char *property, sd_bus_message *reply, void *userdata,
          sd_bus_error *ret_error)
{
    if (strcmp(property, "Type") == 0)
        return sd_bus_message_append(reply, "s", "peripheral");

    if (strcmp(property, "ServiceUUIDs") == 0)
        return sd_bus_message_append(reply, "as", 1, SVC_UUID);

    if (strcmp(property, "Includes") == 0)
        return sd_bus_message_append(reply, "as", 1, "local-name");

    return -ENOENT;
}

static int
svc_props(sd_bus *bus, const char *path, const char *interface,
          const char *property, sd_bus_message *reply, void *userdata,
          sd_bus_error *ret_error)
{
    if (strcmp(property, "UUID") == 0)
        return sd_bus_message_append(reply, "s", SVC_UUID);

    if (strcmp(property, "Primary") == 0)
        return sd_bus_message_append(reply, "b", true);

    if (strcmp(property, "Includes") == 0)
        return sd_bus_message_append(reply, "ao", 0);

    return -ENOENT;
}

static int
chr_props(sd_bus *bus, const char *path, const char *interface,
          const char *property, sd_bus_message *reply, void *userdata,
          sd_bus_error *ret_error)
{
    if (strcmp(property, "UUID") == 0)
        return sd_bus_message_append(reply, "s", CHR_UUID);

    if (strcmp(property, "Service") == 0)
        return sd_bus_message_append(reply, "o", SVC_PATH);

    if (strcmp(property, "Flags") == 0)
        return sd_bus_message_append(reply, "as", CHR_NFLAG, CHR_FLAGS);

    return -ENOENT;
}

static int
chr_notsup(sd_bus_message *m, void *misc, sd_bus_error *err)
{
    return sd_bus_error_set(
               err, "org.bluez.Error.NotSupported", "Not supported"
           );
}

static int
event(uinput input, uint16_t k, bool down)
{
    const struct input_event evts[] = {
        { .type = EV_SYN },
        { .type = EV_KEY, .code = k, .value = down },
    };

    for (size_t i = 0; i < COUNT(evts) && evts[i].code != KEY_UNKNOWN; i++) {
        ssize_t r = write(input, &evts[i], sizeof(evts[i]));
        if (r < 0)
            return -errno;
    }

    usleep(50000);
    return down ? event(input, k, false) : 0;
}

static int
chr_writevalue(sd_bus_message *m, void *misc, sd_bus_error *err)
{
    const uint8_t *bytes = NULL;
    uinput *input = misc;
    size_t size = 0;
    int r;

    r = sd_bus_message_has_signature(m, "aya{sv}");
    if (r < 0)
        return r;

    r = sd_bus_message_read_array(m, 'y', (const void **) &bytes, &size);
    if (r < 0)
        return r;

    if (size == 0 || size > 32) {
        WARN("Invalid write length: %zu", size);
        return sd_bus_reply_method_errorf(
                   m, "org.bluez.Error.InvalidValueLength", "Invalid value length"
               );
    }

    /* Validate input. */
    for (size_t i = 0; i < size; i++) {
        if (char2key(bytes[i]) == KEY_UNKNOWN) {
            DEBUG("Unknown KeyCode: code %u", bytes[i]);
            return sd_bus_reply_method_errorf(
                       m, "org.bluez.Error.NotPermitted", "Invalid value"
                   );
        }
    }

    for (size_t i = 0; i < size && r >= 0; i++) {
        DEBUG("Sending key: %c -> code %u", bytes[i], char2key(bytes[i]));
        r = event(*input, char2key(bytes[i]), true);
    }
    if (r >= 0)
        r = event(*input, KEY_ENTER, true);
    if (r >= 0)
        r = event(*input, KEY_UNKNOWN, false);
    if (r < 0) {
        DEBUG("Write failed");
        return sd_bus_reply_method_errorf(
                   m, "org.bluez.Error.Failed", "Write failed"
               );
    }

    return sd_bus_reply_method_return(m, "");
}

static int
meth_noop(sd_bus_message *m, void *misc, sd_bus_error *err)
{
    return sd_bus_reply_method_return(m, "");
}

static const sd_bus_vtable adv_vtable[] = {
    SD_BUS_VTABLE_START(0),
    PROP("Type", "s", adv_props),
    PROP("ServiceUUIDs", "as", adv_props),
    PROP("Includes", "as", adv_props),
    METH("Release", "", "", meth_noop),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable svc_vtable[] = {
    SD_BUS_VTABLE_START(0),
    PROP("UUID", "s", svc_props),
    PROP("Primary", "b", svc_props),
    PROP("Includes", "ao", svc_props),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable chr_vtable[] = {
    SD_BUS_VTABLE_START(0),
    PROP("UUID", "s", chr_props),
    PROP("Service", "o", chr_props),
    PROP("Flags", "as", chr_props),
    METH("ReadValue", "a{sv}", "ay", chr_notsup),
    METH("WriteValue", "aya{sv}", "", chr_writevalue),
    METH("StartNotify", "", "", chr_notsup),
    METH("StopNotify", "", "", meth_noop),
    SD_BUS_VTABLE_END
};

static int
on_reply(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    if (sd_bus_error_is_set(ret_error))
        ERROR("Error registering: %s: %s\n",
              ret_error->name, ret_error->message);

    return 0;
}

static int
on_bt_iface(sd_bus_message *m, void *bus, sd_bus_error *ret_error)
{
    const char *obj = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oa{sa{sv}}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sa{sv}")) > 0) {
        const char *iface = NULL;

        r = sd_bus_message_read(m, "s", &iface);
        if (r < 0)
            return r;

        r = sd_bus_message_skip(m, "a{sv}");
        if (r < 0)
            return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;

        if (strcmp(iface, "org.bluez.GattManager1") == 0) {
            r = sd_bus_call_method_async(bus, NULL, "org.bluez", obj, iface,
                                         "RegisterApplication", on_reply, NULL,
                                         "oa{sv}", MAN_PATH, 0);
            if (r < 0)
                return r;
            DEBUG("Registering object %s with BlueZ on %s", obj, iface);
        }

        if (strcmp(iface, "org.bluez.LEAdvertisingManager1") == 0) {
            r = sd_bus_call_method_async(bus, NULL, "org.bluez", obj, iface,
                                         "RegisterAdvertisement", on_reply, NULL,
                                         "oa{sv}", ADV_PATH, 0);
            if (r < 0)
                return r;
            DEBUG("Registering object %s with BlueZ on %s", obj, iface);
        }
    }
    if (r < 0)
        return r;

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static void
setup_uinput(uinput *input)
{
    static const struct uinput_user_dev dev = {
        .name = "Jelling",
        .id = {
            .bustype = BUS_USB,
            .vendor = 0xef0f,
            .product = 0xd746,
            .version = 1
        }
    };

    static const char *devices[] = {
        "/dev/input/uinput",
        "/dev/uinput",
        "/dev/misc/uinput",
        NULL
    };

    SCOPED(uinput) fd = -1;
    int r;

    for (size_t i = 0; fd < 0; i++) {
        fd = open(devices[i], O_WRONLY);
        if (fd < 0) {
            if (errno == ENOENT)
                continue;
            ABORT(errno, "Error opening %s", devices[i]);
        }
    }
    if (fd < 0)
        ABORT(errno, "Error finding uevent");

    DEBUG("uevent opened at fd %d", fd);
    r = ioctl(fd, UI_SET_EVBIT, EV_KEY);
    if (r < 0)
        ABORT(errno, "Error setting uinput KEY type");

    r = ioctl(fd, UI_SET_EVBIT, EV_SYN);
    if (r < 0)
        ABORT(errno, "Error setting uinput SYN type");

    for (uint8_t c = 0; c < UINT8_MAX; c++) {
        uint16_t k = char2key(c);
        if (k == KEY_UNKNOWN) {
            if (c != '\n')
                continue;
            k = KEY_ENTER;
        }

        r = ioctl(fd, UI_SET_KEYBIT, k);
        if (r < 0)
            ABORT(errno, "Error setting uinput keybit: %c", c);
    }

    r = write(fd, &dev, sizeof(dev));
    if (r < 0)
        ABORT(errno, "Error writing uinput device description");

    r = ioctl(fd, UI_DEV_CREATE);
    if (r < 0)
        ABORT(errno, "Error creating uinput device");

    *input = fd;
    fd = -1;
}

static void
setup_objects(sd_bus *bus, uinput *i)
{
    int r;

    r = sd_bus_add_object_manager(bus, NULL, MAN_PATH);
    if (r < 0)
        ABORT(-r, "Error adding object manager");

    r = sd_bus_add_object_vtable(bus, NULL, ADV_PATH,
                                 "org.bluez.LEAdvertisement1",
                                 adv_vtable, i);
    if (r < 0)
        ABORT(-r, "Error creating advertisement");

    r = sd_bus_add_object_vtable(bus, NULL, SVC_PATH,
                                 "org.bluez.GattService1",
                                 svc_vtable, i);
    if (r < 0)
        ABORT(-r, "Error creating service");

    r = sd_bus_add_object_vtable(bus, NULL, CHR_PATH,
                                 "org.bluez.GattCharacteristic1",
                                 chr_vtable, i);
    if (r < 0)
        ABORT(-r, "Error creating characteristic");
}

static void
setup_registration(sd_bus *bus)
{
    SCOPED(sd_bus_message) *msg = NULL;
    int r;

    r = sd_bus_add_match(bus, NULL, MATCH, on_bt_iface, bus);
    if (r < 0)
        ABORT(-r, "Error registering for bluetooth interfaces");

    r = sd_bus_call_method(bus, "org.bluez", "/",
                           "org.freedesktop.DBus.ObjectManager",
                           "GetManagedObjects", NULL, &msg, "");
    if (r < 0)
        ABORT(-r, "Error calling bluez ObjectManager");

    r = sd_bus_message_enter_container(msg, 'a', "{oa{sa{sv}}}");
    if (r < 0)
        ABORT(-r, "Error parsing bluez results");

    while ((r = sd_bus_message_enter_container(msg, 'e', "oa{sa{sv}}")) > 0) {
        r = on_bt_iface(msg, bus, NULL);
        if (r < 0)
            ABORT(-r, "Error parsing bluez results");

        r = sd_bus_message_exit_container(msg);
        if (r < 0)
            ABORT(-r, "Error parsing bluez results");
    }
    if (r < 0)
        ABORT(-r, "Error parsing bluez results");

    r = sd_bus_message_exit_container(msg);
    if (r < 0)
        ABORT(-r, "Error parsing bluez results");
}

static int
on_signal(sd_event_source* src, const struct signalfd_siginfo* sig, void *loop)
{
    DEBUG("Signal %d caught", sig->ssi_signo);
    return 0;
}


static int
on_term(sd_event_source* src, const struct signalfd_siginfo* sig, void *loop)
{
    DEBUG("Termination signal %d received, exiting loop", sig->ssi_signo);
    sd_event_exit((sd_event*)loop, 0);
    return 0;
}

int
main(int argc, char *argv[])
{
    SCOPED(sd_event) *loop = NULL;
    SCOPED(sd_bus) *bus = NULL;
    SCOPED(uinput) i = -1;
    int r;

    r = sd_event_default(&loop);
    if (r < 0)
        ABORT(-r, "Error creating event loop");

    sd_event_add_signal(loop, NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, on_signal, loop);
    sd_event_add_signal(loop, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, on_term, loop);
    sd_event_add_signal(loop, NULL, SIGPIPE| SD_EVENT_SIGNAL_PROCMASK, on_signal, loop);
    sd_event_add_signal(loop, NULL, SIGTERM| SD_EVENT_SIGNAL_PROCMASK, on_term, loop);
    sd_event_add_signal(loop, NULL, SIGUSR1| SD_EVENT_SIGNAL_PROCMASK, on_signal, loop);
    sd_event_add_signal(loop, NULL, SIGUSR2| SD_EVENT_SIGNAL_PROCMASK, on_signal, loop);

    r = sd_bus_default_system(&bus);
    if (r < 0)
        ABORT(-r, "Error connecting to system bus");

#if ENABLE_DEBUG
    r = sd_bus_request_name(bus, "org.fedorahosted.freeotp.jelling", 0);
    if (r < 0)
        ABORT(-r, "Error claiming busname");
#endif

    r = sd_bus_attach_event(bus, loop, 0);
    if (r < 0)
        ABORT(-r, "Error attaching bus to event loop");

    setup_uinput(&i);
    setup_objects(bus, &i);
    setup_registration(bus);

    DEBUG("Entering main event loop");
    r = sd_event_loop(loop);
    if (r < 0)
        ABORT(-r, "Error running event loop");

    return EXIT_SUCCESS;
}
