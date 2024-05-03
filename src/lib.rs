use std::{
    ffi::c_void,
    mem::size_of,
    ptr::{addr_of, addr_of_mut, null_mut},
};

use windows::Win32::Foundation::{
    HANDLE, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_ADDRESS, STATUS_NOT_FOUND,
};

pub const DEVICE_NAME: &str = "\\\\.\\wnbios\0";

pub type PhysicalAddr = usize;
pub type VirtualAddr = *mut c_void;

pub type Result<T> = windows::core::Result<T>;

pub type NtQuerySystemInformation = unsafe fn(
    SystemInformationClass: u32,
    SystemInformation: *mut c_void,
    SystemInformationLength: u32,
    ReturnLength: *mut u32,
) -> NTSTATUS;

pub type DeviceIoControl = unsafe fn(
    device: HANDLE,
    ioctl_code: u32,
    input: *const c_void,
    input_size: u32,
    output: *mut c_void,
    output_size: u32,
    bytes_returned: *mut u32,
) -> NTSTATUS;

#[repr(C)]
struct WnBiosMem {
    size: usize,
    addr: PhysicalAddr,
    unk1: usize,
    out_ptr: VirtualAddr,
    unk2: usize,
}

#[repr(C)]
struct SystemHandleTableEntryInfoEx {
    object: VirtualAddr,
    unique_process_id: u32,
    handle_value: u32,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
pub struct EprocessOffsets {
    pub active_process_link: usize,
    pub virtual_size: usize,
    pub image_file_name: usize,
    pub unique_process_id: usize,
    pub section_base_address: usize,
}

pub struct WnBios {
    handle: HANDLE,
    offsets: EprocessOffsets,
    cr3: PhysicalAddr,
    process_list: VirtualAddr,
    ntqsi: NtQuerySystemInformation,
    ioctl: DeviceIoControl,
}

pub struct Process<'a> {
    wnbios: &'a WnBios,
    cr3: PhysicalAddr,
    eprocess: VirtualAddr,
}

impl WnBios {
    /// Creates a new wrapper around the WnBios driver.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver, get the system CR3, or leak an eprocess.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    pub unsafe fn new(
        handle: HANDLE,
        offsets: EprocessOffsets,
        ntqsi: NtQuerySystemInformation,
        ioctl: DeviceIoControl,
    ) -> Result<Self> {
        let mut wnbios = Self {
            handle,
            offsets,
            cr3: 0,
            process_list: null_mut(),
            ntqsi,
            ioctl,
        };

        wnbios.cr3 = wnbios.get_system_cr3()?;

        wnbios.process_list = wnbios.leak_eprocess()?.add(offsets.active_process_link);

        Ok(wnbios)
    }

    /// Reads some bytes from the given physical address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read_physical_bytes(
        &self,
        addr: PhysicalAddr,
        output: *mut u8,
        size: usize,
    ) -> Result<()> {
        let mem = self.map_physical(addr, size)?;
        std::ptr::copy(mem.out_ptr as _, output, size);
        self.unmap_physical(mem)
    }

    /// Reads some memory as a given type from the given physical address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read_physical<T>(&self, addr: PhysicalAddr) -> Result<T> {
        let mut output: T = std::mem::zeroed();
        self.read_physical_bytes(addr, addr_of_mut!(output) as _, size_of::<T>())?;
        Ok(output)
    }

    /// Writes some bytes to the given physical address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write_physical_bytes(
        &self,
        addr: PhysicalAddr,
        data: *const u8,
        size: usize,
    ) -> Result<()> {
        let mem = self.map_physical(addr, size)?;
        std::ptr::copy(data, mem.out_ptr as _, size);
        self.unmap_physical(mem)
    }

    /// Writes some memory as a given type to the given physical address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write_physical<T>(&self, addr: PhysicalAddr, data: &T) -> Result<()> {
        self.write_physical_bytes(addr, data as *const T as _, size_of::<T>())
    }

    /// Reads some bytes from the given virtual address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read_virtual_bytes(
        &self,
        addr: VirtualAddr,
        output: *mut u8,
        size: usize,
    ) -> Result<()> {
        self.read_physical_bytes(self.virtual_to_physical(self.cr3, addr)?, output, size)
    }

    /// Reads some memory as a given type from the given virtual address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read_virtual<T>(&self, addr: VirtualAddr) -> Result<T> {
        self.read_physical(self.virtual_to_physical(self.cr3, addr)?)
    }

    /// Writes some bytes to the given virtual address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write_virtual_bytes(
        &self,
        addr: VirtualAddr,
        data: *const u8,
        size: usize,
    ) -> Result<()> {
        self.write_physical_bytes(self.virtual_to_physical(self.cr3, addr)?, data, size)
    }

    /// Writes some memory as a given type to the given virtual address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write_virtual<T>(&self, addr: VirtualAddr, data: &T) -> Result<()> {
        self.write_physical(self.virtual_to_physical(self.cr3, addr)?, data)
    }

    /// Finds and opens the process with the given process ID.
    ///
    /// # Errors
    ///
    /// This function will return an error if it can't find the process or can't talk to the driver.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    pub unsafe fn open_process(&self, process_id: u32) -> Result<Process> {
        let list_head = self.process_list;
        let mut current = list_head;
        let mut started = false;

        while !started || current != list_head {
            if !started {
                started = true;
            }

            self.read_virtual_bytes(
                current,
                addr_of_mut!(current) as _,
                size_of::<VirtualAddr>(),
            )?;

            let eprocess = current.sub(self.offsets.active_process_link);
            let virtual_size: usize = self.read_virtual(eprocess.add(self.offsets.virtual_size))?;

            // ignore unsized processes
            if virtual_size == 0 {
                continue;
            }

            let pid: usize = self.read_virtual(eprocess.add(self.offsets.unique_process_id))?;

            if process_id == (pid as u32) {
                let cr3: PhysicalAddr =
                    self.read_virtual(eprocess.add(self.offsets.section_base_address))?;

                return Ok(Process {
                    wnbios: self,
                    cr3,
                    eprocess,
                });
            }
        }

        Err(STATUS_NOT_FOUND.to_hresult().into())
    }

    unsafe fn map_physical(&self, addr: PhysicalAddr, size: usize) -> Result<WnBiosMem> {
        const IOCTL_MAP: u32 = 0x80102040;
        const MEM_SIZE: u32 = size_of::<WnBiosMem>() as _;

        let mut mem: WnBiosMem = std::mem::zeroed();

        mem.addr = addr;
        mem.size = size;

        let mut _out_size = 0;
        (self.ioctl)(
            self.handle,
            IOCTL_MAP,
            addr_of!(mem) as _,
            MEM_SIZE,
            addr_of_mut!(mem) as _,
            MEM_SIZE,
            addr_of_mut!(_out_size),
        )
        .ok()?;

        if mem.out_ptr.is_null() {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        Ok(mem)
    }

    unsafe fn unmap_physical(&self, mem: WnBiosMem) -> Result<()> {
        const IOCTL_UNMAP: u32 = 0x80102044;
        const MEM_SIZE: u32 = size_of::<WnBiosMem>() as _;

        let mut _out_size = 0;
        (self.ioctl)(
            self.handle,
            IOCTL_UNMAP,
            addr_of!(mem) as _,
            MEM_SIZE,
            null_mut(),
            0,
            addr_of_mut!(_out_size),
        )
        .ok()
    }

    unsafe fn get_system_cr3(&self) -> Result<PhysicalAddr> {
        for i in 0..10 {
            let mem: WnBiosMem = self.map_physical(i * 0x10_000, 0x10_000)?;
            let buffer = mem.out_ptr;

            for offset in (0..0x10_000).step_by(0x1_000) {
                if 0x00000001000600E9 ^ (0xffffffffffff00ff & *buffer.add(offset).cast::<u64>())
                    != 0
                {
                    continue;
                }

                if 0xfffff80000000000
                    ^ (0xfffff80000000000 & *buffer.add(offset + 0x70).cast::<u64>())
                    != 0
                {
                    continue;
                }

                let addr = *buffer.add(offset + 0xa0).cast::<u64>();

                if 0xffffff0000000fff & addr != 0 {
                    continue;
                }

                return Ok(addr as _);
            }

            self.unmap_physical(mem)?;
        }

        Err(STATUS_NOT_FOUND.to_hresult().into())
    }

    unsafe fn leak_eprocess(&self) -> Result<VirtualAddr> {
        const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 0x40;
        const SYSTEM_UNIQUE_RESERVED: u32 = 4;
        const SYSTEM_KPROCESS_HANDLE_ATTRIBUTES: u32 = 0x102A;
        const SANITY_CHECK: u32 = 3;

        let mut data = Vec::<u8>::new();
        let mut data_size = 0;
        loop {
            if let Err(e) = (self.ntqsi)(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                data.as_mut_ptr() as _,
                data_size,
                &mut data_size,
            )
            .ok()
            {
                if e.code() != STATUS_INFO_LENGTH_MISMATCH.to_hresult() {
                    return Err(e);
                } else {
                    data = vec![0u8; data_size as _];
                    continue;
                }
            }
            break;
        }

        let number_of_handles = *data.as_ptr().cast::<u32>();
        let handles = data.as_ptr().add(8).cast::<SystemHandleTableEntryInfoEx>();

        for handle in std::slice::from_raw_parts(handles, number_of_handles as _) {
            if handle.unique_process_id != SYSTEM_UNIQUE_RESERVED
                || handle.handle_attributes != SYSTEM_KPROCESS_HANDLE_ATTRIBUTES
            {
                continue;
            }

            let check: u32 = self.read_virtual(handle.object)?;

            if check == SANITY_CHECK {
                return Ok(handle.object);
            }
        }

        Err(STATUS_NOT_FOUND.to_hresult().into())
    }

    /// Attempts to map a virtual address to a physical address, based on a given CR3.
    ///
    /// Information from https://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html
    ///
    /// In order to map a virtual address to a physical address, we have to do some fun memory traversing.
    /// In order to do *that* we have to break the virtual address down into its components.
    ///
    /// Starting from the value stored in the CR3 register (which is per process), we immediately gain access to the PML4.
    /// The offset that we want into the PML4 is stored with 9 bits of the virtual address.
    /// We can take that offset, multiply it by 8 (the number of bytes in an entry), and index into the PML4 to get the entry we want.
    /// We can then look into the entry and extract the page offset from the CR3 of the PDPT we want.
    ///
    /// Repeating the process, we get the PDPT entry offset from the virtual address, to get the PD CR3 offset, and get the PD entry offset, to get the PT CR3 offset, to get the PT entry offset, to finally get the final actual page of memory.
    ///
    /// Now, there are some edge cases.
    /// There's the page size flag, which *I think* indicates that the given page is a huge page, and can be read directly.
    /// If so, then there's a bug in the below code, because it's checking bit 1<<7, instead of 1<<56.
    ///
    /// ```txt
    /// Control Register 3
    ///       (CR3)
    ///         |
    ///         v
    ///  Page Map Level 4    Page Directory Pointer Table     Page Directory              Page Table              Page of memory
    ///       (PML4)                    (PDPT)                     (PD)                      (PT)                  (4096 bytes)
    /// +----------------+   +--->+----------------+   +--->+----------------+   +--->+----------------+   +--->+----------------+
    /// |     pml4e0     |   |    |     pdpte0     |   |    |      pde0      |   |    |      pte0      |   |    |                |
    /// |----------------|   |    |----------------|   |    |----------------|   |    |----------------|   |    |                |
    /// |     pml4e1     |   |    |     pdpte1     |   |    |      pde1      |   |    |      pte1      |   |    |                |
    /// |----------------|   |    |----------------|   |    |----------------|   |    |----------------|   |    |                |
    /// |     pml4e2     |   |    |     pdpte2     |   |    |      pde2      |   |    |      pte2      |   |    |                |
    /// |----------------|   |    |----------------|   |    |----------------|   |    |----------------|   |    |      ....      |
    /// |     pml4e3     |   |    |     pdpte3     |   |    |      pde3      |   |    |      pte3      |   |    |                |
    /// |----------------|   |    |----------------|   |    |----------------|   |    |----------------|   |    |                |
    /// |      ....      |---+    |      ....      |---+    |      ....      |---+    |      ....      |---+    |                |
    /// |----------------|        |----------------|        |----------------|        |----------------|        |                |
    /// |    pml4e511    |        |    pdpte511    |        |     pde511     |        |     pte511     |        |                |
    /// +----------------+        +----------------+        +----------------+        +----------------+        +----------------+
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [Virtual Address]
    ///   ^^^^^^^^ ^^^^^^^^                                                        pointer metadata (mode mapping)
    ///                     ^^^^^^^^ ^                                             page map level 4 offset
    ///                               ^^^^^^^ ^^                                   page directory pointer offset
    ///                                         ^^^^^^ ^^^                         page directory offset
    ///                                                   ^^^^^ ^^^^               page table offset
    ///                                                             ^^^^ ^^^^^^^^  page offset
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PML4 Entry]
    ///   ^                                                                        region is valid
    ///    ^                                                                       writes allowed
    ///     ^                                                                      user mode access allowed
    ///      ^                                                                     write through
    ///       ^                                                                    cache disabled
    ///        ^                                                                   in use/accessed
    ///         ^                                                                  (unused)
    ///          ^                                                                 page size (must be 0)
    ///            ^^^^                                                            (unused)
    ///                ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^                    page frame number (CR3 offset to the PDPT)
    ///                                                         ^^^^               reserved
    ///                                                             ^^^^ ^^^^^^^   (unused)
    ///                                                                         ^  execution disabled
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PDPT Entry]
    ///   ^                                                                        region is valid
    ///    ^                                                                       writes allowed
    ///     ^                                                                      user mode access allowed
    ///      ^                                                                     write through
    ///       ^                                                                    cache disabled
    ///        ^                                                                   in use/accessed
    ///         ^                                                                  (unused)
    ///          ^                                                                 page size (1 = 1GiB)
    ///            ^^^^                                                            (unused)
    ///                ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^                    page frame number (CR3 offset to the PD)
    ///                                                         ^^^^               reserved
    ///                                                             ^^^^ ^^^^^^^   (unused)
    ///                                                                         ^  execution disabled
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PD Entry]
    ///   ^                                                                        region is valid
    ///    ^                                                                       writes allowed
    ///     ^                                                                      user mode access allowed
    ///      ^                                                                     write through
    ///       ^                                                                    cache disabled
    ///        ^                                                                   in use/accessed
    ///         ^                                                                  (unused)
    ///          ^                                                                 page size (1 = 2MiB)
    ///            ^^^^                                                            (unused)
    ///                ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^                    page frame number (CR3 offset to the PT)
    ///                                                         ^^^^               reserved
    ///                                                             ^^^^ ^^^^^^^   (unused)
    ///                                                                         ^  execution disabled
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PT Entry]
    ///   ^                                                                        region is valid
    ///    ^                                                                       writes allowed
    ///     ^                                                                      user mode access allowed
    ///      ^                                                                     write through
    ///       ^                                                                    cache disabled
    ///        ^                                                                   in use/accessed
    ///         ^                                                                  dirty (page has been written)
    ///          ^                                                                 page access type
    ///            ^                                                               translations are global
    ///             ^^^                                                            (unused)
    ///                ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^                    page frame number (CR3 offset to the physical page)
    ///                                                         ^^^^               reserved
    ///                                                             ^^^^ ^^^       (unused)
    ///                                                                     ^^^^   protection key
    ///                                                                         ^  execution disabled
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the address attempting to be read looks invalid.
    ///
    /// # Safety
    ///
    /// This is _probably_ safe, but we are messing with physical memory here.
    unsafe fn virtual_to_physical(
        &self,
        cr3: PhysicalAddr,
        va: VirtualAddr,
    ) -> Result<PhysicalAddr> {
        let va = va as usize;

        let pml4 = (va >> 39) & 0x1ff;

        let pml4e =
            self.read_physical::<PhysicalAddr>(cr3 + pml4 * std::mem::size_of::<usize>())?;
        if pml4e == 0 {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        let directory_ptr = (va >> 30) & 0x1ff;

        let pdpte = self.read_physical::<PhysicalAddr>(
            (pml4e & 0xFFFFFFFFFF000) + directory_ptr * std::mem::size_of::<usize>(),
        )?;
        if pdpte == 0 {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        if (pdpte & (1 << 7)) != 0 {
            return Ok((pdpte & 0xFFFFFC0000000) + (va & 0x3FFFFFFF));
        }

        let directory = (va >> 21) & 0x1ff;

        let pde = self.read_physical::<PhysicalAddr>(
            (pdpte & 0xFFFFFFFFFF000) + directory * std::mem::size_of::<usize>(),
        )?;
        if pde == 0 {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        if (pde & (1 << 7)) != 0 {
            return Ok((pde & 0xFFFFFFFE00000) + (va & 0x1FFFFF));
        }

        let table = (va >> 12) & 0x1ff;

        let pte = self.read_physical::<PhysicalAddr>(
            (pde & 0xFFFFFFFFFF000) + table * std::mem::size_of::<usize>(),
        )?;

        if pte == 0 {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        Ok((pte & 0xFFFFFFFFFF000) + (va & 0xFFF))
    }
}

impl<'a> Process<'a> {
    /// Reads bytes from the given address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read_bytes(&self, addr: VirtualAddr, output: *mut u8, size: usize) -> Result<()> {
        let phys = self.wnbios.virtual_to_physical(self.cr3, addr)?;
        self.wnbios.read_physical_bytes(phys, output, size)
    }

    /// Reads data as the given type from the given address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn read<T>(&self, addr: VirtualAddr) -> Result<T> {
        let phys = self.wnbios.virtual_to_physical(self.cr3, addr)?;
        self.wnbios.read_physical(phys)
    }

    /// Writes bytes to the given address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write_bytes(
        &self,
        addr: VirtualAddr,
        data: *const u8,
        size: usize,
    ) -> Result<()> {
        let phys = self.wnbios.virtual_to_physical(self.cr3, addr)?;
        self.wnbios.write_physical_bytes(phys, data, size)
    }

    /// Writes data as the given type to the given address.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub unsafe fn write<T>(&self, addr: VirtualAddr, data: &T) -> Result<()> {
        let phys = self.wnbios.virtual_to_physical(self.cr3, addr)?;
        self.wnbios.write_physical(phys, data)
    }

    #[inline]
    pub const fn get_eprocess_ptr(&self) -> VirtualAddr {
        self.eprocess
    }
}
