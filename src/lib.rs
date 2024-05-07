use std::{
    ffi::c_void,
    mem::{size_of, size_of_val},
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
struct TableEntry(u64);

/// Windows-version-dependent offsets into the EPROCESS struct
/// Check <https://www.vergiliusproject.com/kernels/x64/Windows%2011/23H2%20(2023%20Update)/_EPROCESS> for the ones you want
#[derive(Clone, Copy)]
pub struct EprocessOffsets {
    pub active_process_link: usize,
    pub virtual_size: usize,
    pub unique_process_id: usize,
    pub directory_table: usize,
}

pub struct WnBios {
    handle: HANDLE,
    offsets: EprocessOffsets,
    cr3: PhysicalAddr,
    process_list: VirtualAddr,
    ntqsi: NtQuerySystemInformation,
    ioctl: DeviceIoControl,
}

impl WnBios {
    /// Creates a new wrapper around the WnBios driver.
    /// This takes function pointers for [`NtQuerySystemInformation`] and [`DeviceIoControl`] functions so that you can do fun syscall stuff if you want to.
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
        self.unmap_physical(mem)?;

        Ok(())
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

    /// Reads some bytes from the given virtual address, taking care across page boundaries.
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
        let mut current_addr = addr;
        let mut current_output = output;
        let mut remaining = size;

        while remaining > 0 {
            let to_read = remaining.min(0x1000 - (current_addr as usize & 0xfff));

            #[cfg(debug_assertions)]
            println!("[WnBios::read_virtual_bytes] Reading 0x{to_read:x} from {current_addr:?} to {current_output:?}");

            self.read_physical_bytes(
                self.virtual_to_physical(self.cr3, current_addr)?,
                current_output,
                to_read,
            )?;

            current_addr = current_addr.add(to_read);
            current_output = current_output.add(to_read);
            remaining -= to_read;
        }

        Ok(())
    }

    /// Reads some memory as a given type from the given virtual address, taking care across page boundaries.
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
        let mut output: T = std::mem::zeroed();
        self.read_virtual_bytes(addr, addr_of_mut!(output) as _, size_of::<T>())?;
        Ok(output)
    }

    /// Writes some bytes to the given virtual address, taking care across page boundaries.
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
        let mut current_addr = addr;
        let mut current_input = data;
        let mut remaining = size;

        while remaining > 0 {
            let to_write = remaining.min(0x1000 - (current_addr as usize & 0xfff));

            #[cfg(debug_assertions)]
            println!("[WnBios::write_virtual_bytes] Writing 0x{to_write:x} bytes to {current_addr:?} from {current_input:?}");

            self.write_physical_bytes(
                self.virtual_to_physical(self.cr3, current_addr)?,
                current_input,
                to_write,
            )?;
            current_addr = current_addr.add(to_write);
            current_input = current_input.add(to_write);
            remaining -= to_write;
        }

        Ok(())
    }

    /// Writes some memory as a given type to the given virtual address, taking care across page boundaries.
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
        self.write_virtual_bytes(addr, data as *const T as _, size_of::<T>())
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
                    self.read_virtual(eprocess.add(self.offsets.directory_table))?;

                return Ok(Process {
                    wnbios: self,
                    cr3,
                    eprocess,
                });
            }
        }

        Err(STATUS_NOT_FOUND.to_hresult().into())
    }

    /// Uses the WnBios driver to map the given physical memory to a virtual address that's available to the current process.
    ///
    /// # Errors
    ///
    /// This function will return an error if the driver cannot be contacted or the address it returns is null.
    /// This could also cause an error if the memory cannot be mapped.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
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

    /// Unmaps the physical memory.
    /// Remember to call this when you're done with accessing the memory!
    ///
    /// # Errors
    ///
    /// This function will return an error if the driver cannot be contacted.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
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

    /// Leaks the CR3 value for the kernel.
    ///
    /// This uses the "low stub" technique, which searches for the DOS "low stub" in the low regions of physical memory.
    /// The "low stub" follows a general format, which the code below searches for.
    ///
    /// # Errors
    ///
    /// This function will return an error if the driver cannot be contacted or the system CR3 cannot be found.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    unsafe fn get_system_cr3(&self) -> Result<PhysicalAddr> {
        for i in 0..10 {
            let mem: WnBiosMem = self.map_physical(i * 0x10_000, 0x10_000)?;
            let buffer = mem.out_ptr;

            for offset in (0..0x10_000).step_by(0x1_000) {
                // check if KPROCESSOR_START_BLOCK starts with a JMP instruction to the end of the block (e9), and that KPROCESSOR_START_BLOCK->CompletionFlag == 1
                if (*buffer.add(offset).cast::<u64>() & 0xffff_ffff_ffff_00ff)
                    != 0x0000_0001_0006_00e9
                {
                    continue;
                }

                // check if KPROCESSOR_START_BLOCK->LmFlag looks sane
                if (*buffer.add(offset + 0x70).cast::<u64>() & 0xffff_f800_0000_0003)
                    != 0xffff_f800_0000_0000
                {
                    continue;
                }

                // read KPROCESSOR_START_BLOCK->KSPECIAL_REGISTERS->CR3 to get the physical address where the PML4 resides
                let addr = *buffer.add(offset + 0xa0).cast::<u64>();

                // does it look somewhat sane?
                if addr & 0xffff_ff00_0000_0fff != 0 {
                    continue;
                }

                return Ok(addr as _);
            }

            self.unmap_physical(mem)?;
        }

        Err(STATUS_NOT_FOUND.to_hresult().into())
    }

    /// Queries the system extended handle information to leak a pointer to an EPROCESS struct.
    /// This should be in the system VA space.
    ///
    /// # Errors
    ///
    /// This function will return an error if the driver cannot be contacted, the system information cannot be queried, or if nothing gets leaked.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    unsafe fn leak_eprocess(&self) -> Result<VirtualAddr> {
        const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 0x40;
        const SYSTEM_UNIQUE_RESERVED: u32 = 4; // process ID of the system
        const SYSTEM_KPROCESS_HANDLE_ATTRIBUTES: u32 = 0x102A; // OBJ_DONT_REPARSE|OBJ_EXCLUSIVE|OBJ_NO_RIGHTS_UPGRADE|OBJ_INHERIT
        const KOBJECTS_PROCESS: u32 = 3;

        // Loop until we actually allocate enough memory for this call
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

        // The first four bytes are the number of handles
        let number_of_handles = *data.as_ptr().cast::<u32>();
        // There's four bytes of reserved data after that
        // Then there are our handle info structs
        let handles = data.as_ptr().add(8).cast::<SystemHandleTableEntryInfoEx>();

        for handle in std::slice::from_raw_parts(handles, number_of_handles as _) {
            // We only want handles owned by the system with the specific attributes
            if handle.unique_process_id != SYSTEM_UNIQUE_RESERVED
                || handle.handle_attributes != SYSTEM_KPROCESS_HANDLE_ATTRIBUTES
            {
                continue;
            }

            let check: u32 = self.read_virtual(handle.object)?; // I think it should really be a u8 comparison here, but eh, it works

            // Check if the object type is a process
            if check == KOBJECTS_PROCESS {
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
    ///   ^                                                                        execution disabled
    ///    ^^^^^^^ ^^^^                                                            (unused)
    ///                ^^^^                                                        reserved
    ///                     ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^               page frame number (CR3 offset to the PT)
    ///                                                             ^^^^           (unused)
    ///                                                                  ^         page size (must be 0)
    ///                                                                   ^        (unused)
    ///                                                                    ^       in use/accessed
    ///                                                                     ^      cache disabled
    ///                                                                      ^     write through
    ///                                                                       ^    user mode access allowed
    ///                                                                        ^   writes allowed
    ///                                                                         ^  region is valid
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PDPT Entry]
    ///   ^                                                                        execution disabled
    ///    ^^^^^^^ ^^^^                                                            (unused)
    ///                ^^^^                                                        reserved
    ///                     ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^               page frame number (CR3 offset to the PT)
    ///                                                             ^^^^           (unused)
    ///                                                                  ^         page size (1 = 1GiB)
    ///                                                                   ^        dirty (page has been written. ignored if page size = 0)
    ///                                                                    ^       in use/accessed
    ///                                                                     ^      cache disabled
    ///                                                                      ^     write through
    ///                                                                       ^    user mode access allowed
    ///                                                                        ^   writes allowed
    ///                                                                         ^  region is valid
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PD Entry]
    ///   ^                                                                        execution disabled
    ///    ^^^^^^^ ^^^^                                                            (unused)
    ///                ^^^^                                                        reserved
    ///                     ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^               page frame number (CR3 offset to the PT)
    ///                                                             ^^^^           (unused)
    ///                                                                  ^         page size (1 = 2MiB)
    ///                                                                   ^        dirty (page has been written. ignored if page size = 0)
    ///                                                                    ^       in use/accessed
    ///                                                                     ^      cache disabled
    ///                                                                      ^     write through
    ///                                                                       ^    user mode access allowed
    ///                                                                        ^   writes allowed
    ///                                                                         ^  region is valid
    ///
    /// 0bxxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx [PT Entry]
    ///   ^                                                                        execution disabled
    ///    ^^^^                                                                    protection key
    ///        ^^^ ^^^^                                                            (unused)
    ///                ^^^^                                                        reserved
    ///                     ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^               page frame number (CR3 offset to the physical page)
    ///                                                             ^^^            (unused)
    ///                                                                ^           translations are global
    ///                                                                  ^         page access type/page attribute table
    ///                                                                   ^        dirty (page has been written)
    ///                                                                    ^       in use/accessed
    ///                                                                     ^      cache disabled
    ///                                                                      ^     write through
    ///                                                                       ^    user mode access allowed
    ///                                                                        ^   writes allowed
    ///                                                                         ^  region is valid
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

        let pml4e = self.read_physical::<TableEntry>(cr3 + pml4 * std::mem::size_of::<usize>())?;
        if pml4e.is_invalid() {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        let directory_ptr = (va >> 30) & 0x1ff;

        let pdpte = self.read_physical::<TableEntry>(
            pml4e.page_frame() + directory_ptr * std::mem::size_of::<usize>(),
        )?;

        if pdpte.is_invalid() {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        if pdpte.large_page() {
            return Ok((pdpte.0 & 0xFFFFFC0000000) as PhysicalAddr + (va & 0x3FFFFFFF));
        }

        let directory = (va >> 21) & 0x1ff;

        let pde = self.read_physical::<TableEntry>(
            pdpte.page_frame() + directory * std::mem::size_of::<usize>(),
        )?;

        if pde.is_invalid() {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        if pde.large_page() {
            return Ok((pde.0 & 0xFFFFFFFE00000) as PhysicalAddr + (va & 0x1FFFFF));
        }

        let table = (va >> 12) & 0x1ff;

        let pte = self
            .read_physical::<TableEntry>(pde.page_frame() + table * std::mem::size_of::<usize>())?;

        if pte.is_invalid() {
            return Err(STATUS_INVALID_ADDRESS.to_hresult().into());
        }

        Ok(pte.page_frame() + (va & 0xFFF))
    }
}

pub struct Process<'a> {
    wnbios: &'a WnBios,
    cr3: PhysicalAddr,
    eprocess: VirtualAddr,
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
        let mut current_addr = addr;
        let mut current_output = output;
        let mut remaining = size;

        while remaining > 0 {
            let to_read = remaining.min(0x1000 - (current_addr as usize & 0xfff));

            #[cfg(debug_assertions)]
            println!("[Process::read_bytes] Reading 0x{to_read:x} bytes from {current_addr:?} to {current_output:?}");

            self.wnbios.read_physical_bytes(
                self.wnbios.virtual_to_physical(self.cr3, current_addr)?,
                current_output,
                to_read,
            )?;
            current_addr = current_addr.add(to_read);
            current_output = current_output.add(to_read);
            remaining -= to_read;
        }

        Ok(())
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
        let mut output: T = std::mem::zeroed();
        self.read_bytes(addr, addr_of_mut!(output) as _, size_of::<T>())?;
        Ok(output)
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
        let mut current_addr = addr;
        let mut current_input = data;
        let mut remaining = size;

        while remaining > 0 {
            let to_write = remaining.min(0x1000 - (current_addr as usize & 0xfff));

            #[cfg(debug_assertions)]
            println!("[Process::write_bytes] Writing 0x{to_write:x} bytes to {current_addr:?} from {current_input:?}");

            self.wnbios.write_physical_bytes(
                self.wnbios.virtual_to_physical(self.cr3, current_addr)?,
                current_input,
                to_write,
            )?;
            current_addr = current_addr.add(to_write);
            current_input = current_input.add(to_write);
            remaining -= to_write;
        }

        Ok(())
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
        self.write_bytes(addr, data as *const T as _, size_of::<T>())
    }

    #[inline]
    pub const fn get_eprocess_ptr(&self) -> VirtualAddr {
        self.eprocess
    }

    /// Returns an iterator for this process' memory regions.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to talk to the driver or if the address is invalid.
    ///
    /// # Safety
    ///
    /// This is all unsafe as hell man.
    #[inline]
    pub fn regions(&self) -> Result<RegionWalker> {
        unsafe {
            let pml4: [TableEntry; 512] = self.wnbios.read_physical(self.cr3)?;

            Ok(RegionWalker {
                process: self,
                pml4,
                pdpt: std::mem::zeroed(),
                pd: std::mem::zeroed(),
                pt: std::mem::zeroed(),
                pml4_offset: 0,
                pdpt_offset: 0,
                pd_offset: 0,
                pt_offset: 0,
            })
        }
    }
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_memory_basic_information
#[repr(C)]
#[derive(Debug)]
pub struct MemoryInformation {
    pub base_address: *mut c_void,
    pub region_size: usize,
    pub readable: bool,
    pub writeable: bool,
    pub executable: bool,
    pub present: bool,
    pub accessed: bool,
    pub dirty: bool,
}

impl Default for MemoryInformation {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[inline]
const fn physical_to_virtual(pml4o: usize, pdpto: usize, pdo: usize, pto: usize) -> VirtualAddr {
    (pml4o << 39 | pdpto << 30 | pdo << 21 | pto << 12) as _
}

pub struct RegionWalker<'a> {
    process: &'a Process<'a>,
    pml4: [TableEntry; 512],
    pdpt: [TableEntry; 512],
    pd: [TableEntry; 512],
    pt: [TableEntry; 512],
    pml4_offset: usize,
    pdpt_offset: usize,
    pd_offset: usize,
    pt_offset: usize,
}

impl<'a> Iterator for RegionWalker<'a> {
    type Item = MemoryInformation;

    fn next(&mut self) -> Option<Self::Item> {
        // 256..512 supported but not used. I think it's because the user-accessible pages are listed in the top half
        if self.pml4_offset >= 256 {
            return None;
        }

        // traverse down the PML4 from the stored offset
        for pml4o in self.pml4_offset..256 {
            let pml4e = self.pml4[pml4o];

            // check if the entry is valid, otherwise skipping to the next one
            if pml4e.is_invalid() {
                self.pdpt_offset = 0;
                self.pd_offset = 0;
                self.pt_offset = 0;
                continue;
            }

            // todo: proper caching so we don't have to re-read this all the damn time
            unsafe {
                self.process.wnbios.read_physical_bytes(
                    pml4e.page_frame(),
                    self.pdpt.as_mut_ptr() as _,
                    size_of_val(&self.pdpt),
                )
            }
            .unwrap();

            // traverse down the PDPT from the stored offset
            for pdpto in self.pdpt_offset..512 {
                let pdpte = self.pdpt[pdpto];

                // check if the entry is valid, otherwise skipping to the next one
                if pdpte.is_invalid() {
                    self.pd_offset = 0;
                    self.pt_offset = 0;
                    continue;
                }

                // check if it's using 1GiB pages, because if so we don't need to look into the PD or PT
                if pdpte.large_page() {
                    let mut num_pages = 1;
                    for i in (pdpto + 1)..512 {
                        // if the attributes don't look the same, then it's not one large allocation
                        if self.pdpt[i].attrs() != pdpte.attrs() {
                            break;
                        }

                        // note: this doesn't necessarily mean that the pages are contiguous. we'd have to check the differences in the page frame for that

                        num_pages += 1;
                    }

                    let base_address = physical_to_virtual(pml4o, pdpto, 0, 0);
                    let region_size = num_pages << 30;

                    // increment and reset all the offsets

                    self.pml4_offset = pml4o;
                    self.pdpt_offset = pdpto + num_pages;
                    self.pd_offset = 0;
                    self.pt_offset = 0;

                    if self.pdpt_offset >= 512 {
                        self.pml4_offset += 1;
                        self.pdpt_offset = 0;
                    }

                    return Some(MemoryInformation {
                        base_address,
                        region_size,
                        readable: pdpte.um_accessible(),
                        writeable: pdpte.writeable(),
                        executable: pdpte.executable() && pml4e.executable(),
                        present: pdpte.present(),
                        accessed: pdpte.accessed(),
                        dirty: pdpte.dirty(),
                    });
                }

                // todo: proper caching so we don't have to re-read this all the damn time
                unsafe {
                    self.process.wnbios.read_physical_bytes(
                        pdpte.page_frame(),
                        self.pd.as_mut_ptr() as _,
                        size_of_val(&self.pd),
                    )
                }
                .unwrap();

                // traverse down the PD from the stored offset
                for pdo in self.pd_offset..512 {
                    let pde = self.pd[pdo];

                    // check if the entry is valid, otherwise skipping to the next one
                    if pde.is_invalid() {
                        self.pt_offset = 0;
                        continue;
                    }

                    // check if we're using 2MiB pages, because if so we don't need to look into the PT
                    if pde.large_page() {
                        let mut num_pages = 1;
                        for i in (pdo + 1)..512 {
                            // if the attributes don't look the same, then it's not one large allocation
                            if self.pd[i].attrs() != pde.attrs() {
                                break;
                            }

                            // note: this doesn't necessarily mean that the pages are contiguous. we'd have to check the differences in the page frame for that

                            num_pages += 1;
                        }

                        let base_address = physical_to_virtual(pml4o, pdpto, pdo, 0);
                        let region_size = num_pages << 21;

                        // increment and reset all the offsets

                        self.pml4_offset = pml4o;
                        self.pdpt_offset = pdpto;
                        self.pd_offset = pdo + num_pages;
                        self.pt_offset = 0;

                        if self.pd_offset >= 512 {
                            self.pdpt_offset += 1;
                            self.pd_offset = 0;
                        }

                        if self.pdpt_offset >= 512 {
                            self.pml4_offset += 1;
                            self.pdpt_offset = 0;
                        }

                        return Some(MemoryInformation {
                            base_address,
                            region_size,
                            readable: pde.um_accessible(),
                            writeable: pde.writeable(),
                            executable: pde.executable()
                                && pdpte.executable()
                                && pml4e.executable(),
                            present: pde.present(),
                            accessed: pde.accessed(),
                            dirty: pde.dirty(),
                        });
                    }

                    // todo: proper caching so we don't have to re-read this all the damn time
                    unsafe {
                        self.process.wnbios.read_physical_bytes(
                            pde.page_frame(),
                            self.pt.as_mut_ptr() as _,
                            size_of_val(&self.pt),
                        )
                    }
                    .unwrap();

                    // traverse down the PT from the stored offset
                    for pto in self.pt_offset..512 {
                        let pte = self.pt[pto];

                        // check if the entry is valid, otherwise skipping to the next one
                        if pte.is_invalid() {
                            continue;
                        }

                        let mut num_pages = 1;
                        for i in (pto + 1)..512 {
                            // if the attributes don't look the same, then it's not one large allocation
                            if self.pt[i].attrs() != pte.attrs() {
                                break;
                            }

                            // note: this doesn't necessarily mean that the pages are contiguous. we'd have to check the differences in the page frame for that

                            num_pages += 1;
                        }

                        let base_address = physical_to_virtual(pml4o, pdpto, pdo, pto);
                        let region_size = num_pages << 12;

                        // increment and reset all the offsets

                        self.pml4_offset = pml4o;
                        self.pdpt_offset = pdpto;
                        self.pd_offset = pdo;
                        self.pt_offset = pto + num_pages;

                        if self.pt_offset >= 512 {
                            self.pd_offset += 1;
                            self.pt_offset = 0;
                        }

                        if self.pd_offset >= 512 {
                            self.pdpt_offset += 1;
                            self.pd_offset = 0;
                        }

                        if self.pdpt_offset >= 512 {
                            self.pml4_offset += 1;
                            self.pdpt_offset = 0;
                        }

                        return Some(MemoryInformation {
                            base_address,
                            region_size,
                            readable: pte.um_accessible(),
                            writeable: pte.writeable(),
                            executable: pte.executable()
                                && pde.executable()
                                && pdpte.executable()
                                && pml4e.executable(),
                            present: pte.present(),
                            accessed: pte.accessed(),
                            dirty: pte.dirty(),
                        });
                    }

                    // if we got this far, all of the checked PT entries were invalid. reset the PT offset for the next PD loop
                    self.pt_offset = 0;
                }

                // if we got this far, all of the checked PD and PT entries were invalid. reset the PD and PT offsets for the next PDPT loop
                self.pd_offset = 0;
                self.pt_offset = 0;
            }

            // if we got this far, all of the checked PDPT, PD, and PT entries were invalid. reset these offsets for the next PML4 loop
            self.pdpt_offset = 0;
            self.pd_offset = 0;
            self.pt_offset = 0;
        }

        // at this stage we've iterated to the end of the PML4, so we're done
        None
    }
}

impl TableEntry {
    #[inline]
    const fn present(&self) -> bool {
        (self.0 & 1) != 0
    }

    #[inline]
    const fn writeable(&self) -> bool {
        (self.0 & (1 << 1)) != 0
    }

    #[inline]
    const fn um_accessible(&self) -> bool {
        (self.0 & (1 << 2)) != 0
    }

    #[inline]
    const fn accessed(&self) -> bool {
        (self.0 & (1 << 5)) != 0
    }

    #[inline]
    const fn dirty(&self) -> bool {
        (self.0 & (1 << 6)) != 0
    }

    /// Only valid for PDPT and PD entries
    #[inline]
    const fn large_page(&self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    #[inline]
    const fn page_frame(&self) -> usize {
        (self.0 & 0xFFFFFFFFFF000) as _
    }

    #[inline]
    const fn executable(&self) -> bool {
        (self.0 & (1 << 63)) == 0
    }

    #[inline]
    const fn is_invalid(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    const fn attrs(&self) -> u64 {
        self.0 & (1 << 63 | 0xfff)
    }
}
