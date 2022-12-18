import threading
import select
import pyudev
import functools
import usb.core


class USBListenCustomThread(threading.Thread):

    def __init__(self, permission):
        threading.Thread.__init__(self)
        self.permission = permission
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.start()

    def run(self) -> None:
        fds = {self.monitor.fileno(): self.monitor}
        while True:
            r, w, x = select.select(fds, [], [])
            if self.monitor.fileno() in r:
                r.remove(self.monitor.fileno())
                for device in iter(functools.partial(self.monitor.poll, 0), None):
                    if not device.device_node:
                        break
                    print("Udev:", self.monitor.poll())
                    for name in (i['NAME'] for i in device.ancestors if 'NAME' in i):
                        print("Plugged-in device name:", name)
                        print("Action:", device.action)
                        if "add" in device.action:
                            print("Device_node:", device.device_node)
                            # inputDevice = evdev.InputDevice(device.device_node)
                            # throw error , device.device_node not in /dev/input
                            print("Device:", device.subsystem)
                            product_id = device.get("ID_MODEL_ID")
                            vendor_id = device.get("ID_VENDOR_ID")
                            if not (product_id is None or vendor_id is None):
                                items = device.items()
                                vendor_id_new = int(vendor_id, 16)
                                product_id_new = int(product_id, 16)
                                print(f"Product_id:{product_id}, Vendor_id:{vendor_id}")
                                myDevice = usb.core.find(idVendor=vendor_id_new, idProduct=product_id_new)
                                if myDevice is not None and not self.permission:
                                    print("Disable usb...")
                                    try:
                                        myDevice.detach_kernel_driver(0)
                                    except usb.core.USBError as e:
                                        print(e)
