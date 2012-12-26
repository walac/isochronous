#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define LIBUSB_CHECK(expr) libusb_check(#expr, expr, __LINE__, __FILE__)

#define IDVENDOR 0x04d8
#define IDPRODUCT 0xfa2e
#define EPOUT 0x01
#define EPIN 0x81

static int
libusb_check(const char *expr, int ec, size_t line, const char *filepath)
{
    if (ec != LIBUSB_SUCCESS) {
        const size_t expr_size = strlen(expr) + 1;
        char fn[expr_size];

        memcpy(fn, expr, expr_size * sizeof(char));
        *strchrnul(fn, '(') = '\0';

        const size_t filepath_size = strlen(filepath) + 1;
        char file[filepath_size];

        memcpy(file, filepath, filepath_size * sizeof(char));

        fprintf(stderr, "%s(%zu): %s\n", basename(file), line, libusb_error_name(ec));
        exit(EXIT_FAILURE);
    }

    return ec;
}

static void
onexit(void)
{
    libusb_exit(NULL);
}

static void *
create_dummy_data(size_t size)
{
    uint8_t *data = calloc(size, sizeof(uint8_t));
    assert(data);

    uint8_t ch = 0;
    for (size_t i = 0; i < size; ++i)
        data[i] = ch++;

    return data;
}

static int
get_packet_length(libusb_device *dev, unsigned char ep)
{
    assert(dev);

    struct libusb_config_descriptor *config;

    LIBUSB_CHECK(libusb_get_active_config_descriptor(dev, &config));

    assert(3 == config->interface[0].num_altsetting);

    const struct libusb_interface_descriptor *intf = config->interface[0].altsetting + 2;

    int packet_size = 0;

    for (int i = 0; i < intf->bNumEndpoints; ++i) {
        const struct libusb_endpoint_descriptor *endpoint = intf->endpoint + i;
        if (endpoint->bEndpointAddress == ep) {
            packet_size = endpoint->wMaxPacketSize;
            break;
        }
    }

    assert(packet_size);
    return packet_size;
}

static int
get_packet_count(size_t length, int packet_size)
{
    return (length / packet_size) + (length % packet_size != 0);
}

static libusb_device_handle *
setup_bm_device(void)
{
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(
                                        NULL, IDVENDOR, IDPRODUCT);

    if (!handle)
        return NULL;

    LIBUSB_CHECK(libusb_set_configuration(handle, 1));
    LIBUSB_CHECK(libusb_claim_interface(handle, 0));
    LIBUSB_CHECK(libusb_set_interface_alt_setting(handle, 0, 2));

    return handle;
}

static void
close_device(libusb_device_handle *handle)
{
    LIBUSB_CHECK(libusb_release_interface(handle, 0));
    libusb_close(handle);
}

static void
transfer_cb(struct libusb_transfer *transfer)
{
    for (int i = 0; i < transfer->num_iso_packets; ++i) {
        struct libusb_iso_packet_descriptor *ipd = transfer->iso_packet_desc + i;

        if (LIBUSB_TRANSFER_COMPLETED == ipd->status) {
            printf("Packet %d requested to transfer %u bytes, transfered %u bytes.\n",
                    i, ipd->length, ipd->actual_length);
        } else {
            fprintf(stderr, "Packet %d failed to transfer: status = %d.\n",
                    i, (int) ipd->status);
        }
    }

    *(int *) transfer->user_data = 1;
}

static void
write_data(libusb_device_handle *handle, size_t n)
{
    libusb_device *dev = libusb_get_device(handle);
    assert(dev);
    const int packet_length = get_packet_length(dev, EPOUT); 
    const int packet_count = get_packet_count(n, packet_length);
    int completed = 0;

    struct libusb_transfer *transfer = libusb_alloc_transfer(packet_count);
    assert(transfer);

    void *p = create_dummy_data(n);

    libusb_fill_iso_transfer(
        transfer,
        handle,
        EPOUT,
        p,
        n,
        packet_count,
        transfer_cb,
        &completed,
        10000);

    libusb_set_iso_packet_lengths(transfer, packet_length);
    LIBUSB_CHECK(libusb_submit_transfer(transfer));

    while (!completed)
        libusb_handle_events_completed(NULL, NULL);

    libusb_free_transfer(transfer);
    free(p);
}

static void
read_data(libusb_device_handle *handle, size_t n)
{
    libusb_device *dev = libusb_get_device(handle);
    assert(dev);
    const int packet_length = get_packet_length(dev, EPIN); 
    const int packet_count = get_packet_count(n, packet_length);
    int completed = 0;

    struct libusb_transfer *transfer = libusb_alloc_transfer(packet_count);
    assert(transfer);

    void *p = calloc(n, sizeof(uint8_t));

    libusb_fill_iso_transfer(
        transfer,
        handle,
        EPIN,
        p,
        n,
        packet_count,
        transfer_cb,
        &completed,
        10000);

    libusb_set_iso_packet_lengths(transfer, packet_length);
    LIBUSB_CHECK(libusb_submit_transfer(transfer));

    while (!completed)
        libusb_handle_events_completed(NULL, NULL);

    libusb_free_transfer(transfer);
    free(p);
}

int
main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    LIBUSB_CHECK(libusb_init(NULL));
    atexit(onexit);

    libusb_device_handle *dev = setup_bm_device();
    assert(dev);

    write_data(dev, 128);
    read_data(dev, 128);
    close_device(dev);
}

