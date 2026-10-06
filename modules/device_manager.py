from database.db import (
    create_device,
    get_all_devices,
    get_device,
    get_device_by_ip,
    search_devices,
    get_devices_by_status,
    update_device,
    delete_device,
    delete_device_by_ip,
    get_device_statistics,
)


# ============================================================
# DEVICE MANAGER
# ============================================================

class DeviceManager:
    """
    Lớp quản lý thiết bị.

    Chức năng:
        - Add device
        - Get devices
        - Search device
        - Filter status
        - Update device
        - Delete device
        - Statistics
    """

    def __init__(self):
        pass

    # ========================================================
    # CREATE
    # ========================================================

    def add_device(
        self,
        ip,
        hostname="",
        mac="",
        status="Unknown",
        duration=None
    ):
        """
        Thêm thiết bị mới.
        """

        ip = ip.strip()
        hostname = hostname.strip()
        mac = mac.strip()
        status = status.strip()

        if not ip:
            return {
                "success": False,
                "message": "IP Address không được để trống."
            }

        # Kiểm tra IP đã tồn tại
        existing = get_device_by_ip(ip)

        if existing:
            return {
                "success": False,
                "message": f"IP {ip} đã tồn tại."
            }

        device_id = create_device(
            ip=ip,
            hostname=hostname,
            mac=mac,
            status=status,
            duration=duration
        )

        if device_id is None:
            return {
                "success": False,
                "message": "Không thể thêm thiết bị."
            }

        return {
            "success": True,
            "message": "Thêm thiết bị thành công.",
            "device_id": device_id
        }

    # ========================================================
    # READ ALL
    # ========================================================

    def get_devices(self):
        """
        Lấy toàn bộ thiết bị.
        """

        return get_all_devices()

    # ========================================================
    # READ ONE
    # ========================================================

    def get_device(self, device_id):
        """
        Lấy một thiết bị theo ID.
        """

        return get_device(device_id)

    # ========================================================
    # SEARCH
    # ========================================================

    def search(self, keyword):
        """
        Tìm kiếm theo:
            - IP
            - Hostname
            - MAC
        """

        keyword = keyword.strip()

        if not keyword:
            return self.get_devices()

        return search_devices(keyword)

    # ========================================================
    # FILTER STATUS
    # ========================================================

    def filter_status(self, status):
        """
        Lọc thiết bị theo trạng thái.

        status:
            All
            Online
            Offline
        """

        status = status.strip()

        if status == "" or status == "All":
            return self.get_devices()

        return get_devices_by_status(status)

    # ========================================================
    # SEARCH + FILTER
    # ========================================================

    def search_and_filter(
        self,
        keyword="",
        status="All"
    ):
        """
        Tìm kiếm + lọc trạng thái.
        """

        keyword = keyword.strip()
        status = status.strip()

        devices = self.get_devices()

        # ----------------------------------------------------
        # Search
        # ----------------------------------------------------

        if keyword:

            keyword_lower = keyword.lower()

            filtered_devices = []

            for device in devices:

                ip = str(device.get("ip") or "").lower()
                hostname = str(
                    device.get("hostname") or ""
                ).lower()
                mac = str(
                    device.get("mac") or ""
                ).lower()

                if (
                    keyword_lower in ip
                    or keyword_lower in hostname
                    or keyword_lower in mac
                ):
                    filtered_devices.append(device)

            devices = filtered_devices

        # ----------------------------------------------------
        # Status filter
        # ----------------------------------------------------

        if status and status != "All":

            devices = [
                device
                for device in devices
                if device.get("status") == status
            ]

        return devices

    # ========================================================
    # UPDATE
    # ========================================================

    def edit_device(
        self,
        device_id,
        ip=None,
        hostname=None,
        mac=None,
        status=None,
        duration=None
    ):
        """
        Cập nhật thiết bị.
        """

        device = get_device(device_id)

        if device is None:
            return {
                "success": False,
                "message": "Không tìm thấy thiết bị."
            }

        # ----------------------------------------------------
        # Kiểm tra IP mới
        # ----------------------------------------------------

        if ip is not None:

            ip = ip.strip()

            if not ip:
                return {
                    "success": False,
                    "message": "IP Address không được để trống."
                }

            existing = get_device_by_ip(ip)

            if (
                existing
                and existing["id"] != device_id
            ):
                return {
                    "success": False,
                    "message": f"IP {ip} đã được sử dụng."
                }

        # ----------------------------------------------------
        # Update
        # ----------------------------------------------------

        success = update_device(
            device_id=device_id,
            ip=ip,
            hostname=hostname,
            mac=mac,
            status=status,
            duration=duration
        )

        if not success:
            return {
                "success": False,
                "message": "Cập nhật thiết bị thất bại."
            }

        return {
            "success": True,
            "message": "Cập nhật thiết bị thành công."
        }

    # ========================================================
    # DELETE
    # ========================================================

    def remove_device(self, device_id):
        """
        Xóa thiết bị theo ID.
        """

        device = get_device(device_id)

        if device is None:
            return {
                "success": False,
                "message": "Không tìm thấy thiết bị."
            }

        success = delete_device(device_id)

        if not success:
            return {
                "success": False,
                "message": "Xóa thiết bị thất bại."
            }

        return {
            "success": True,
            "message": "Xóa thiết bị thành công."
        }

    # ========================================================
    # DELETE BY IP
    # ========================================================

    def remove_device_by_ip(self, ip):
        """
        Xóa thiết bị theo IP.
        """

        ip = ip.strip()

        device = get_device_by_ip(ip)

        if device is None:
            return {
                "success": False,
                "message": f"Không tìm thấy IP {ip}."
            }

        success = delete_device_by_ip(ip)

        if not success:
            return {
                "success": False,
                "message": "Xóa thiết bị thất bại."
            }

        return {
            "success": True,
            "message": "Xóa thiết bị thành công."
        }

    # ========================================================
    # STATISTICS
    # ========================================================

    def statistics(self):
        """
        Lấy thống kê thiết bị.
        """

        return get_device_statistics()


# ============================================================
# GLOBAL DEVICE MANAGER
# ============================================================

device_manager = DeviceManager()