#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>

#define LIBUSB_CHECK(expr) libusb_check(#expr, expr, __LINE__, __FILE__)

#define IDVENDOR 0x04d8
#define IDPRODUCT 0xfa2e
#define IFACE 0
#define ALTS 2
#define EPOUT 0x03
#define EPIN 0x83

static int verbose;

static int
libusb_check(const char *expr, int ec, size_t line, const char *filepath)
{
    if (ec != LIBUSB_SUCCESS) {
        const size_t expr_size = strlen(expr) + 1;
        char fn[expr_size];

        memcpy(fn, expr, expr_size * sizeof(char));
        char *p = strchr(fn, '(');

        if (p)
            *p = '\0';

        const size_t filepath_size = strlen(filepath) + 1;
        char file[filepath_size];

        memcpy(file, filepath, filepath_size * sizeof(char));

        fprintf(stderr, "%s(%zu): %s\n", basename(file), line, libusb_error_name(ec));
        exit(EXIT_FAILURE);
    }

    return ec;
}

static void
exit_handler(void)
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
get_packet_length(libusb_device *dev, unsigned char ep, int iface, int alts)
{
    assert(dev);

    struct libusb_config_descriptor *config;

    LIBUSB_CHECK(libusb_get_active_config_descriptor(dev, &config));

    assert(alts < config->interface[iface].num_altsetting);

    const struct libusb_interface_descriptor *intf = config->interface[iface].altsetting + alts;

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
    return length ? (length / packet_size) + (length % packet_size != 0) : 0;
}

static libusb_device_handle *
setup_bm_device(uint16_t vid, uint16_t pid, int iface, int alts)
{
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(
                                        NULL, vid, pid);

    if (!handle)
        return NULL;

    LIBUSB_CHECK(libusb_set_configuration(handle, 1));
    LIBUSB_CHECK(libusb_claim_interface(handle, iface));
    LIBUSB_CHECK(libusb_set_interface_alt_setting(handle, iface, alts));

    return handle;
}

static void
close_device(libusb_device_handle *handle, int iface)
{
    LIBUSB_CHECK(libusb_release_interface(handle, iface));
    libusb_close(handle);
}

static void
transfer_cb(struct libusb_transfer *transfer)
{
    for (int i = 0; i < transfer->num_iso_packets; ++i) {
        struct libusb_iso_packet_descriptor *ipd = transfer->iso_packet_desc + i;

        if (LIBUSB_TRANSFER_COMPLETED == ipd->status) {
            printf("Packet %d endpoint %02x requested transfer %u bytes, transferred %u bytes.\n",
                    i, transfer->endpoint, ipd->length, ipd->actual_length);
        } else {
            fprintf(stderr, "Packet %d on endpoint %02x failed to transfer: status = %d.\n",
                    i, transfer->endpoint, (int) ipd->status);
        }
    }

    *(int *) transfer->user_data = 1;
}

static void
set_packet_lengths(struct libusb_transfer *transfer, size_t n, size_t len)
{
    libusb_set_iso_packet_lengths(transfer, len);
    const size_t r = n % len;
    if (r)
        transfer->iso_packet_desc[transfer->num_iso_packets - 1].length = r;
}

static void
write_data(libusb_device_handle *handle, int ep, int packet_length, size_t n)
{
    if (!n)
        n = packet_length;

    const int packet_count = get_packet_count(n, packet_length);
    int completed = 0;

    struct libusb_transfer *transfer = libusb_alloc_transfer(packet_count);
    assert(transfer);

    void *p = create_dummy_data(n);

    libusb_fill_iso_transfer(
        transfer,
        handle,
        ep,
        p,
        n,
        packet_count,
        transfer_cb,
        &completed,
        10000);

    set_packet_lengths(transfer, n, packet_length);
    LIBUSB_CHECK(libusb_submit_transfer(transfer));

    while (!completed)
        libusb_handle_events_completed(NULL, NULL);

    libusb_free_transfer(transfer);
    free(p);
}

static void
read_data(libusb_device_handle *handle, int ep, int packet_length, size_t n)
{
    /*
     * Transfer one packet if n is zero
     */
    if (!n)
        n = packet_length;

    const int packet_count = get_packet_count(n, packet_length);
    int completed = 0;

    struct libusb_transfer *transfer = libusb_alloc_transfer(packet_count);
    assert(transfer);

    uint8_t *p = calloc(n, sizeof(uint8_t));

    libusb_fill_iso_transfer(
        transfer,
        handle,
        ep,
        p,
        n,
        packet_count,
        transfer_cb,
        &completed,
        10000);

    set_packet_lengths(transfer, n, packet_length);
    LIBUSB_CHECK(libusb_submit_transfer(transfer));

    while (!completed)
        libusb_handle_events_completed(NULL, NULL);

    libusb_free_transfer(transfer);

    if (verbose) {
        unsigned int i;
        for (i = 0; i < n; i++) {
            printf(" %02x", p[i]);
            if (i % 16 == 15)
                printf("\n");
        }
        printf("\n");
    }
    free(p);
}

int
main(int argc, char **argv)
{
    const char optstr[] = "n:vd:i:a:e:u:";
    size_t n = 0;
    int opt;
    int in_only = 0, out_only = 0;
    uint16_t vid = IDVENDOR;
    uint16_t pid = IDPRODUCT;
    int iface = IFACE;
    int alts = ALTS;
    int ep_in = EPIN;
    int ep_out = EPOUT;

    while ((opt = getopt(argc, argv, optstr)) != -1)
        switch (opt)
        {
            case 'n':
                n = atoi(optarg);
                break;

            case 'v':
                verbose = 1;
                break;

            case 'd':
		{
		    char *rem;
		    vid = (uint16_t) strtoul(optarg, &rem, 16);
		    pid = 0;
		    if (*rem == ':')
			    pid = (uint16_t) strtoul(++rem, NULL, 16);
		}
                break;

            case 'i':
		iface = strtol(optarg, NULL, 0);
                break;

            case 'a':
		alts = strtol(optarg, NULL, 0);
                break;

            case 'e':
		ep_in = strtol(optarg, NULL, 16) | 0x80;
                break;

            case 'u':
		ep_out = strtol(optarg, NULL, 16);
                break;

            default:
                exit(EXIT_FAILURE);
        }
    if (optind != argc) {
        if (argv[optind][0] == 'i')
            in_only = 1;
        else if (argv[optind][0] == 'o')
            out_only = 1;
    }

    LIBUSB_CHECK(libusb_init(NULL));
    atexit(exit_handler);

    libusb_device_handle *devh = setup_bm_device(vid, pid, iface, alts);
    assert(devh);

    libusb_device *dev = libusb_get_device(devh);
    assert(dev);

    if (!in_only) {
        int packet_length_out = get_packet_length(dev, ep_out, iface, alts);
        write_data(devh, ep_out, packet_length_out, n);
    }
    if (!out_only) {
        int packet_length_in = get_packet_length(dev, ep_in, iface, alts);
        read_data(devh, ep_in, packet_length_in, n);
    }

    close_device(devh, iface);
}

