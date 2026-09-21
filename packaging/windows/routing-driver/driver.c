// SirinVPN's WFP bind-redirection driver. No named device, IOCTL, packet
// payload, socket relay, allocation in classify, or persistent state is exposed.
#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>

// Must match crates/windows-service/src/application_driver.rs. The raw context
// contains only the ABI tag and this installation's private IPv4 source address.
static const GUID BIND_KEY = {0x6e6de0cd, 0x25db, 0x48fb, {0xa0, 0x0c, 0x3b, 0xa2, 0x16, 0x77, 0x14, 0x52}};
#define CONTEXT_TAG 0x53560101UL

static UINT32 callout_id;
static PDEVICE_OBJECT device;

static void block(FWPS_CLASSIFY_OUT0 *out) {
    out->actionType = FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static void NTAPI classify(
    const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    void *layer_data,
    const void *classify_context,
    const FWPS_FILTER1 *filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0 *out
) {
    UINT64 handle = 0;
    FWPS_BIND_REQUEST0 *request = NULL;
    UINT32 source;
    const UCHAR *octets;
    SOCKADDR_IN *local;
    NTSTATUS status;
    BOOLEAN allowed = FALSE;
    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);
    if ((out->rights & FWPS_RIGHT_ACTION_WRITE) == 0) return;
    if (values->layerId != FWPS_LAYER_ALE_BIND_REDIRECT_V4 || classify_context == NULL
        || (UINT32)(filter->context >> 32) != CONTEXT_TAG) { block(out); return; }
    source = (UINT32)filter->context;
    octets = (const UCHAR *)&source;
    if (octets[0] != 10 || octets[1] != 77 || octets[2] != 0 || octets[3] < 2 || octets[3] > 254) {
        block(out); return;
    }
    status = FwpsAcquireClassifyHandle0((void *)classify_context, 0, &handle);
    if (!NT_SUCCESS(status)) { block(out); return; }
    status = FwpsAcquireWritableLayerDataPointer0(handle, filter->filterId, 0, (void **)&request, out);
    if (NT_SUCCESS(status) && request != NULL) {
        local = (SOCKADDR_IN *)&request->localAddressAndPort;
        if (local->sin_family == AF_INET) {
            const UCHAR *address = (const UCHAR *)&local->sin_addr.S_un.S_addr;
            if (address[0] == 127) {
                // Explicit loopback IPC remains local. Apps delegating external
                // networking to another executable must select that executable too.
                allowed = TRUE;
            } else if (local->sin_addr.S_un.S_addr == 0 || local->sin_addr.S_un.S_addr == source) {
                local->sin_addr.S_un.S_addr = source;
                allowed = TRUE;
            }
        }
        // Acquisition temporarily blocks classification and removes write
        // rights. Set the final decision before applying the writable data,
        // restoring a soft permit so other callouts can still enforce policy.
        if (allowed) {
            out->actionType = FWP_ACTION_PERMIT;
            out->rights |= FWPS_RIGHT_ACTION_WRITE;
        } else {
            block(out);
        }
        // WFP requires this after every successful acquisition, even if a
        // conflicting explicit bind was rejected without modifying its fields.
        FwpsApplyModifiedLayerData0(handle, request, 0);
    } else {
        block(out);
    }
    FwpsReleaseClassifyHandle0(handle);
}

static NTSTATUS NTAPI notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(key);
    if (type == FWPS_CALLOUT_NOTIFY_ADD_FILTER
        && (filter == NULL || (UINT32)(filter->context >> 32) != CONTEXT_TAG)) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static void unload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    // No flow contexts or asynchronous classifications are retained. WFP drains
    // synchronous callbacks before this unregister operation returns.
    if (callout_id != 0) { (void)FwpsCalloutUnregisterById0(callout_id); callout_id = 0; }
    if (device != NULL) { IoDeleteDevice(device); device = NULL; }
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path) {
    FWPS_CALLOUT1 callout = {0};
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry_path);
    // An unnamed device has no user-accessible control surface. It exists only
    // because WFP requires a driver device object when registering a callback.
    status = IoCreateDevice(driver, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) return status;
    callout.calloutKey = BIND_KEY;
    callout.classifyFn = classify;
    callout.notifyFn = notify;
    status = FwpsCalloutRegister1(device, &callout, &callout_id);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); device = NULL; return status; }
    driver->DriverUnload = unload;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
