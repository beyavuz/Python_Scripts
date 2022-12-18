from USBListenCustomThread import USBListenCustomThread

if __name__ == "__main__":
    permission = False
    USBListenCustomThread(permission).start()  # USB girişlerini anlayacak.

    # BU noktada get diyerek harddiske erişmeye çalıştığında hata vereceğiz.
