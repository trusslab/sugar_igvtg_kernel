/*
 * Copyright (C) 2016-2018 University of California, Irvine
 * All Rights Reserved.
 *
 * Authors:
 * Zhihao Yao <z.yao@uci.edu>
 * Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/prints.h>
#include <linux/kvm_host.h>
#include <asm/tlbflush.h>
#include <linux/dma-buf.h>
#include "vgt.h"

#define CPRINTK0(fmt, args...)

#ifdef CONFIG_X86_64

/* from arch/x86/mm/fault.c */

/* modified from arch/x86/mm/fault.c */

/* From arch/x86/mm/fault.c */

/* adopted and modified from arch/x86/mm/fault.c */
pte_t *walk_page_tables(unsigned long address, struct mm_struct *mm)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	CPRINTK0("[1]: mm = %#x\n", (unsigned int) mm);

	if (mm == NULL) /* kernel addresses. */
		pgd = pgd_offset_k(address);
	else		
		pgd = pgd_offset(mm, address);

	if (!pgd_present(*pgd))
		goto bad;

	pud = pud_offset(pgd, address);

	if (!pud_present(*pud) || pud_large(*pud))
		goto bad;

	pmd = pmd_offset(pud, address);

	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto bad;

	pte = pte_offset_kernel(pmd, address);

	CPRINTK0("[2]: pte=%#x\n", pte);
	CPRINTK0("[3]: *pte=%#x\n", *pte);
	return pte;

bad:
	CPRINTK0("[4]: Couldn't get the pte\n");
	return NULL;
}

#endif /* CONFIG_X86_64 */

enum vgt_local_page_states {
	VGT_LOCAL_INVALID = 0,
	VGT_LOCAL_SHARED = 1,
	VGT_LOCAL_MODIFIED = 2
};

#ifdef CONFIG_X86
#define set_pte_ext(ptep, pte, ext) set_pte(ptep, pte)
#ifdef CONFIG_X86_64
#define pte_mkpresent(ptep)         pte_set_flags(ptep, _PAGE_PRESENT | _PAGE_PROTNONE)
#define pte_mknotpresent(ptep)      pte_clear_flags(ptep, _PAGE_PRESENT | _PAGE_PROTNONE)
#else /* CONFIG_X86_64 */
#endif /* CONFIG_X86_64 */

#define PF_WRITE			    1 << 1
static inline int vgt_local_pte_present(pte_t a)
{
	return pte_flags(a) & (_PAGE_PRESENT);
}
#else /* CONFIG_X86 */
PTE_BIT_FUNC(mkpresent, |= L_PTE_PRESENT);
PTE_BIT_FUNC(mknotpresent, &= ~L_PTE_PRESENT); 
#define dfv_pte_present pte_present
#endif /* CONFIG_X86 */

void flush_tlb_page_mm(struct mm_struct *mm, unsigned long start);

static int vgt_local_change_page_state(unsigned long local_addr, int state)
{
	pte_t *ptep;

	if (!current->mm) {
		PRINTK_ERR("Error: current->mm is NULL.\n");
		return -EINVAL;
	}

	ptep = walk_page_tables(local_addr, current->mm);
	
	if (!ptep)
		goto error_no_pte;
			
	switch (state) {
		
	case VGT_LOCAL_SHARED:
		/* grant read-only permissions to the PTE, aka SHARED state */
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
		break;
		
	case VGT_LOCAL_MODIFIED:
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_mkwrite(*ptep), 0);
		break;		
		
	case VGT_LOCAL_INVALID:
	{
		set_pte_ext(ptep, pte_mknotpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
		break;
	}	
	default:
		PRINTK_ERR("Error: unknown state.\n");
		break;
	}

	__native_flush_tlb_single(local_addr); /* only works when called within the right mm */
		
	return 0;
	
error_no_pte:
	if (local_addr < 0xf6000000 || local_addr >= 0xf7000000)
		PRINTK_ERR("Error: PTE is NULL (local_addr = %#lx, state = %d)\n",
							(unsigned long) local_addr, state);
	return -EFAULT;
}

static unsigned long vgt_local_gfn_to_pfn(int vm_id, unsigned long gfn)
{
	pte_t *ptep;
	struct vgt_device *vgt;

	vgt = vmid_2_vgt_device(vm_id);

	/* This can be called from some kernel threads, therefore we can't use current->mm here. */
	ptep = walk_page_tables(gfn << PAGE_SHIFT, vgt->local_mm);

	if (ptep == NULL) {
		PRINTK_ERR("Error: ptep is NULL (gfn = %#lx, vm_id = %d)\n", (unsigned long) gfn, vm_id);
		DUMP_STACK_ERR();
		return 0;
	}

	return pte_pfn(*ptep); 

}

static int vgt_local_pause_domain(int vm_id)
{
	PRINTK_ERR("Not implemented\n");

	/*TODO*/
	return 0;
}

static int vgt_local_shutdown_domain(int vm_id)
{
	PRINTK_ERR("Not implemented\n");

	/*TODO*/
	return 0;
}

enum access_type {
	ACCESS_MMIO = 0,
	ACCESS_PCI_CONFIG = 1
};

struct emulated_range {
	unsigned long start;
	unsigned long end;
	enum access_type atype;
	struct list_head list;
};

static struct emulated_range *add_emulated_range(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, enum access_type atype)
{
	struct emulated_range *erange = NULL;
	
	erange = kmalloc(sizeof(*erange), GFP_KERNEL);
	if (!erange) {
		PRINTK_ERR("Error: could not allocate memory for erange\n");
		return NULL;
	}

	erange->start = start;
	erange->end = end;
	erange->atype = atype;
	
	list_add(&erange->list, &vma->emulated_ranges_list);

	return erange;
}

static bool is_in_emulated_range(struct vm_area_struct *vma, unsigned long address,
				  enum access_type *atype)
{
	struct emulated_range *erange = NULL;
	CPRINTK0("[1]\n");

	list_for_each_entry(erange, &vma->emulated_ranges_list, list) {
		if (address >= erange->start &&
		    address < erange->end) {
			*atype = erange->atype;
			return true;
		}
	}

	return false;
}

static int remove_emulated_range(struct vm_area_struct *vma,
				 unsigned long start, unsigned long end)
{
	struct emulated_range *erange = NULL, *e_tmp;
	
	list_for_each_entry_safe(erange, e_tmp, &vma->emulated_ranges_list, list) {
		if (erange->start == start && erange->end == end) {
			list_del(&erange->list);
			kfree(erange);
			return 0;
		}
	}

	return -EINVAL;
}

static bool is_emulated_list_empty(struct vm_area_struct *vma)
{
	struct emulated_range *erange = NULL;

	list_for_each_entry(erange, &vma->emulated_ranges_list, list) {
			return false;
	}

	return true;
}

static int __vgt_local_set_trap_area(struct vgt_device *vgt, uint64_t start,
			uint64_t end)
{
	uint64_t _start = start;
	struct vm_area_struct *vma;
	int ret;

	for (; (_start + PAGE_SIZE - 1) <= end; _start += PAGE_SIZE) {
		vgt_local_change_page_state((unsigned long) _start, VGT_LOCAL_INVALID);
	}

	if (_start != (end + 1)) {
		PRINTK_ERR("Error: the trap area was not page aligned (_start = %#lx, end = %#lx)\n",
						(unsigned long) _start, (unsigned long) end);
	}

	vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	if (!vma) {
		PRINTK_ERR("Error: could not allocate memory for vma\n");
		return -ENOMEM;
	}

	vma->vm_start = (unsigned long) start;
	vma->vm_end = (unsigned long) (end + 1);

       	vma->vm_flags = VM_READ | VM_WRITE | VM_MIXEDMAP;
       	vma->vm_page_prot = vm_get_page_prot(PROT_READ | PROT_WRITE);
       	vma->vm_pgoff = 0; 
	vma->vm_file = NULL;
	vma->vm_mm = current->mm;
	vma->vm_ops = NULL;
       	INIT_LIST_HEAD(&vma->anon_vma_chain);
	ret = insert_vm_struct(current->mm, vma);

	if (ret) {
		kfree(vma);
		return -EFAULT;
	}

	vma->emulated_range = HAS_EMULATED_RANGE;
	INIT_LIST_HEAD(&vma->emulated_ranges_list);
	add_emulated_range(vma, (unsigned long) start, (unsigned long) end, ACCESS_MMIO);

	return 0;

}

static int __vgt_local_clear_trap_area(struct vgt_device *vgt, uint64_t start,
			uint64_t end)
{
	uint64_t _start = start;

	for (; (_start + PAGE_SIZE - 1) <= end; _start += PAGE_SIZE) {
		vgt_local_change_page_state((unsigned long) _start, VGT_LOCAL_MODIFIED);
	}

	if (_start != (end + 1)) {
		PRINTK_ERR("Error: the trap area was not page aligned (_start = %#lx, end = %#lx)\n",
						(unsigned long) _start, (unsigned long) end);
	}

	return 0;
}

static int vgt_local_set_trap_area(struct vgt_device *vgt, uint64_t start,
			uint64_t end, bool map)
{
	if (map)
		__vgt_local_set_trap_area(vgt, start, end);
	else
		__vgt_local_clear_trap_area(vgt, start, end);

	return 0;
}

static bool vgt_local_set_guest_page_writeprotection(struct vgt_device *vgt,
			guest_page_t *guest_page)
{
	struct vm_area_struct *vma;
	unsigned long address = guest_page->gfn << PAGE_SHIFT;

	if (!vgt->local_mm) {
		PRINTK_ERR("Error: vgt->local_mm is NULL\n");
		dump_stack();
		return false;
	}

	vma = find_vma(vgt->local_mm, address);
	if (!vma) {
		PRINTK_ERR("Error: could not find the corresponding vma\n");
		return false;
	}

	vgt_local_change_page_state(address, VGT_LOCAL_SHARED);

	if (vma->emulated_range != HAS_EMULATED_RANGE) {
		INIT_LIST_HEAD(&vma->emulated_ranges_list);
		vma->emulated_range = HAS_EMULATED_RANGE;
	}
	add_emulated_range(vma, address, address + PAGE_SIZE, ACCESS_MMIO);
	
	guest_page->writeprotection = true;
	atomic_inc(&vgt->gtt.n_write_protected_guest_page);

	return true;
}

static bool vgt_local_clear_guest_page_writeprotection(struct vgt_device *vgt,
			guest_page_t *guest_page)
{
	struct vm_area_struct *vma;
	unsigned long address = guest_page->gfn << PAGE_SHIFT;

	if (!vgt->local_mm) {
		PRINTK_ERR("Error: vgt->local_mm is NULL\n");
		dump_stack();
		return false;
	}

	vma = find_vma(vgt->local_mm, address);
	if (!vma) {
		PRINTK_ERR("Error: could not find the corresponding vma\n");
		return false;
	}

	vgt_local_change_page_state(address, VGT_LOCAL_MODIFIED);

	remove_emulated_range(vma, address, address + PAGE_SIZE);
	if (is_emulated_list_empty(vma)) {
		vma->emulated_range = 0;
	}

	guest_page->writeprotection = false;
	atomic_dec(&vgt->gtt.n_write_protected_guest_page);

	return true;
}

/* NOTE:
 * It's actually impossible to check if we are running in KVM host,
 * since the "KVM host" is simply native. So we only dectect guest here.
 */
static int vgt_local_check_host(void)
{

	BUG();
	return 0;
}

static int vgt_local_virt_to_pfn(void *addr)
{

	return PFN_DOWN(__pa(addr));
}

static void *vgt_local_pfn_to_virt(int pfn)
{

	return pfn_to_kaddr((unsigned long)pfn);
}

extern int (*vgt_local_access_check)(unsigned long address, unsigned long error_code,
			      struct vm_area_struct *vma, int is_user_addr,
			      struct pt_regs *regs);

int _vgt_local_access_check(unsigned long address, unsigned long error_code,
			   struct vm_area_struct *vma, int is_user_addr,
			   struct pt_regs *regs);

int vgt_local_hvm_counter = 0;

static int vgt_local_hvm_init(struct vgt_device *vgt)
{
	struct vm_area_struct *vma;
	int ret;

	vgt->pci_config_base_addr = vgt->opregion_gpa + 0x2000;
	ret = clear_user((void __user *) vgt->pci_config_base_addr, PAGE_SIZE);

	if (vgt_local_hvm_counter == 0) {
		if (vgt_local_access_check != NULL)
			PRINTK_ERR("Error: vgt_local_access_check is not NULL when it should be.\n");

		vgt_local_access_check = _vgt_local_access_check;
	}
	
	vgt_local_hvm_counter++;

	vma = find_vma(vgt->local_mm, vgt->pci_config_base_addr);
	if (!vma) {
		PRINTK_ERR("Error: could not find vma\n");
		return false;
	}

	vgt_local_change_page_state(vgt->pci_config_base_addr, VGT_LOCAL_INVALID);

	vma->emulated_range = HAS_EMULATED_RANGE;
	INIT_LIST_HEAD(&vma->emulated_ranges_list);
	add_emulated_range(vma, (unsigned long) (vgt->pci_config_base_addr),
				(unsigned long) (vgt->pci_config_base_addr + PAGE_SIZE),
				ACCESS_PCI_CONFIG);

	return 0;
}

static void vgt_local_hvm_exit(struct vgt_device *vgt)
{

	vgt_local_hvm_counter--;

	if (vgt_local_hvm_counter == 0) {
		if (vgt_local_access_check == NULL)
			PRINTK_ERR("Error: vgt_local_access_check is NULL when it shouldn't be.\n");

		vgt_local_access_check = NULL;
	}

}

static void *vgt_local_gpa_to_hva(struct vgt_device *vgt, unsigned long gpa)
{
	unsigned long pfn;

	pfn = vgt_local_gfn_to_pfn(vgt->vm_id, gpa >> PAGE_SHIFT);

	if (!pfn)
		return NULL;

	return (char *)pfn_to_kaddr(pfn) + offset_in_page(gpa);

}

static int vgt_local_inject_msi(struct vgt_device *vgt, u32 addr_lo, u16 data)
{
	int vm_id = vgt->vm_id;

	vgt = vmid_2_vgt_device(vm_id);
	send_sig_info(SIGUSR1, SEND_SIG_FORCED, vgt->local_task);
	return 0;

}

static bool vgt_local_read_hva(struct vgt_device *vgt, void *hva,
			void *data, int len, int atomic)
{

	memcpy(data, hva, len);

	return true;
}

static bool vgt_local_write_hva(struct vgt_device *vgt, void *hva, void *data,
			int len, int atomic)
{

	memcpy(hva, data, len);

	return true;
}

static bool vgt_local_opregion_init(struct vgt_device *vgt)
{
	int rc;
	int i;
	unsigned long addr;

	if (unlikely(vgt->state.opregion_va))
		return true;

	addr = vgt->opregion_gpa; 

	down_read(&(vgt->local_mm->mmap_sem));
	rc = get_user_pages(NULL, vgt->local_mm, addr, VGT_OPREGION_PAGES, 1, 1, vgt->state.opregion_pages, NULL);
	up_read(&vgt->local_mm->mmap_sem);
	if (rc != VGT_OPREGION_PAGES) {
		vgt_err("get_user_pages failed: %d\n", rc);
		return false;
	}

	vgt->state.opregion_va = vmap(vgt->state.opregion_pages, VGT_OPREGION_PAGES, 0, PAGE_KERNEL);
	if (vgt->state.opregion_va == NULL) {
		vgt_err("VM%d: failed to allocate kernel space for opregion\n", vgt->vm_id);
		for (i = 0; i < VGT_OPREGION_PAGES; i++)
			put_page(vgt->state.opregion_pages[i]);
		return false;
	}

	memcpy_fromio(vgt->state.opregion_va, vgt->pdev->opregion_va, VGT_OPREGION_SIZE);
	memcpy(&vgt->state.cfg_space[VGT_REG_CFG_OPREGION], &vgt->opregion_gpa, sizeof(vgt->opregion_gpa));

	/* Note: we should not call put_page here since it will be called later when the instance
	 * is being destroyed in vgt_release_instance() */

	vgt_info("opregion initialized\n");
	return true;
}

static int vgt_local_map_mfn_to_gpfn(struct vgt_device *vgt, int vm_id, unsigned long gpfn,
			unsigned long mfn, int nr, int map, enum map_type type)
{

	int r = 0;
	pte_t *pte, entry;

	switch (type) {
	case VGT_MAP_APERTURE:
	{
		if (map == 1) {
			struct vm_area_struct *vma;
			int ret, i;
	
			vma = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
       			if (!vma) {
				PRINTK_ERR("Error: not enough memory!\n");
				return -ENOMEM;	
       			}
			vma->vm_start = gpfn << PAGE_SHIFT;
       			vma->vm_end = (gpfn + nr) << PAGE_SHIFT;
       			vma->vm_flags = VM_READ | VM_WRITE | VM_MIXEDMAP;
       			vma->vm_page_prot = vm_get_page_prot(PROT_READ | PROT_WRITE);
			vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_NOCACHE);
       			vma->vm_pgoff = 0; 
			vma->vm_file = NULL;
			vma->vm_mm = current->mm;
			vma->vm_ops = NULL;
       			INIT_LIST_HEAD(&vma->anon_vma_chain);
			ret = insert_vm_struct(current->mm, vma);

			for (i = 0; i < nr; i++) {
				ret = vm_insert_mixed(vma, (gpfn + i) << PAGE_SHIFT, mfn + i);
				entry = pte_mkspecial(__pte(((unsigned long) (gpfn + i) << PAGE_SHIFT) | 0x07f));
				pte = walk_page_tables((unsigned long) (gpfn + i) << PAGE_SHIFT, current->mm);
				native_set_pte(pte, entry);
			}

		} else if (map == 0) {
			PRINTK_ERR("Aperture unmap not implemented\n");
		} else {
			PRINTK_ERR("Unexpected value for map (%d)\n", map);
		}

		break;
	}
	case VGT_MAP_OPREGION:
		r = vgt_local_opregion_init(vgt);
		break;
	default:
		vgt_err("type:%d not supported!\n", type);
		r = -EOPNOTSUPP;
	}

	return r;
}

struct kernel_dm vgt_local_kdm = {
	.name = "vgt_local_kdm",
	.g2m_pfn = vgt_local_gfn_to_pfn,
	.pause_domain = vgt_local_pause_domain,
	.shutdown_domain = vgt_local_shutdown_domain,
	.map_mfn_to_gpfn = vgt_local_map_mfn_to_gpfn,
	.set_trap_area = vgt_local_set_trap_area,
	.set_wp_pages = vgt_local_set_guest_page_writeprotection,
	.unset_wp_pages = vgt_local_clear_guest_page_writeprotection,
	.check_host = vgt_local_check_host,
	.from_virt_to_mfn = vgt_local_virt_to_pfn,
	.from_mfn_to_virt = vgt_local_pfn_to_virt,
	.inject_msi = vgt_local_inject_msi,
	.hvm_init = vgt_local_hvm_init,
	.hvm_exit = vgt_local_hvm_exit,
	.gpa_to_va = vgt_local_gpa_to_hva,
	.read_va = vgt_local_read_hva,
	.write_va = vgt_local_write_hva,
};

struct kernel_dm *vgt_local_pkdm = &vgt_local_kdm;
EXPORT_SYMBOL(vgt_local_kdm);

static void vgt_local_emulator_get_fpu(struct x86_emulate_ctxt *ctxt)
{
        preempt_disable();
        /*
         * CR0.TS may reference the host fpu state, not the guest fpu state,
         * so it may be clear at this point.
         */
        clts();
}

static void vgt_local_emulator_put_fpu(struct x86_emulate_ctxt *ctxt)
{
        preempt_enable();
}

struct x86_emulate_ops vgt_local_emulate_ops = {
	.get_fpu = vgt_local_emulator_get_fpu,
	.put_fpu = vgt_local_emulator_put_fpu,
        .read_std = NULL,
        .write_std = NULL,
        .fetch = NULL,
        .read_emulated = NULL,
        .write_emulated = NULL,
        .cmpxchg_emulated = NULL,
        .invlpg = NULL,
        .pio_in_emulated = NULL,
        .pio_out_emulated = NULL,
        .get_segment = NULL,
        .set_segment = NULL,
        .get_cached_segment_base = NULL,
        .get_gdt = NULL,
        .get_idt = NULL,
        .set_gdt = NULL,
        .set_idt = NULL,
        .get_cr = NULL,
        .set_cr = NULL,
        .cpl = NULL,
        .get_dr = NULL,
        .set_dr = NULL,
        .set_msr = NULL,
        .get_msr = NULL,
        .halt = NULL,
        .wbinvd = NULL,
        .fix_hypercall = NULL,
        .intercept = NULL,
};

static int vgt_local_emulate_mem_access(struct pt_regs *regs, int write,
				  struct vm_area_struct *vma, enum access_type atype)
{
	unsigned long num_bytes;
	unsigned char *ip = (unsigned char *) regs->ip;
	unsigned char insns[15];
	int ret;
	struct x86_emulate_ctxt *ctxt = NULL;
	bool success = false;
	unsigned long val;
	struct vgt_device *vgt;

	vgt = vmid_2_vgt_device(current->tgid);

	if (!vgt) {
		PRINTK_ERR("Error: vgt was not found\n");
		return -EINVAL;
	}
	ctxt = vgt->emulate_ctxt;

	CPRINTK0("[1]: vma size = %#lx, pid = %d, tgid = %d\n", vma->vm_end - vma->vm_start, current->pid, current->tgid);
	CPRINTK0("[2]: regs = %#x\n", (unsigned int) regs);
	CPRINTK0("[3]: ip = %#x\n", (unsigned int) ip);
	
	ret = copy_from_user(insns, (unsigned char *) ip, 15);
	if (ret) {
		PRINTK_ERR("Error: copy_from_user failed\n");
		return -ENOMEM;
	}

	CPRINTK0("write = %d\n", write);
	/* Modified from arch/x86/kernel/process_64.c */
	CPRINTK0("RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
		regs->sp, regs->flags);
	CPRINTK0("RAX: %016lx RBX: %016lx RCX: %016lx\n",
		regs->ax, regs->bx, regs->cx);
	CPRINTK0("RDX: %016lx RSI: %016lx RDI: %016lx\n",
		regs->dx, regs->si, regs->di);
	CPRINTK0("RBP: %016lx R08: %016lx R09: %016lx\n",
		regs->bp, regs->r8, regs->r9);
	CPRINTK0("R10: %016lx R11: %016lx R12: %016lx\n",
		regs->r10, regs->r11, regs->r12);
	CPRINTK0("R13: %016lx R14: %016lx R15: %016lx\n",
		regs->r13, regs->r14, regs->r15);

	memset(ctxt, 0x0, sizeof(*ctxt));
	ctxt->eip = regs->ip;
	ctxt->mode = X86EMUL_MODE_PROT64;
	ctxt->ops = &vgt_local_emulate_ops;

        ctxt->_regs[VCPU_REGS_RAX] = regs->ax;
        ctxt->_regs[VCPU_REGS_RCX] = regs->cx;
        ctxt->_regs[VCPU_REGS_RDX] = regs->dx;
        ctxt->_regs[VCPU_REGS_RBX] = regs->bx;
        ctxt->_regs[VCPU_REGS_RSP] = regs->sp;
        ctxt->_regs[VCPU_REGS_RBP] = regs->bp;
        ctxt->_regs[VCPU_REGS_RSI] = regs->si;
        ctxt->_regs[VCPU_REGS_RDI] = regs->di;
#ifdef CONFIG_X86_64
        ctxt->_regs[VCPU_REGS_R8] = regs->r8;
        ctxt->_regs[VCPU_REGS_R9] = regs->r9;
        ctxt->_regs[VCPU_REGS_R10] = regs->r10;
        ctxt->_regs[VCPU_REGS_R11] = regs->r11;
        ctxt->_regs[VCPU_REGS_R12] = regs->r12;
        ctxt->_regs[VCPU_REGS_R13] = regs->r13;
        ctxt->_regs[VCPU_REGS_R14] = regs->r14;
        ctxt->_regs[VCPU_REGS_R15] = regs->r15;
#endif
	ctxt->regs_valid = 0xffff;

	CPRINTK0("before regs->ip = %#lx\n", regs->ip);
	CPRINTK0("before ctxt->eip = %#lx\n", ctxt->eip);
	CPRINTK0("before ctxt->_eip = %#lx\n", ctxt->_eip);

	/* x86_64 instructions can be max 15 bytes */
	ret = x86_decode_insn(ctxt, insns, 15);
	CPRINTK0("x86_decode_insn returned %d\n", ret);

	CPRINTK0("ctxt->src.type = %d\n", ctxt->src.type);
	CPRINTK0("ctxt->src2.type = %d\n", ctxt->src2.type);
	CPRINTK0("ctxt->dst.type = %d\n", ctxt->dst.type);

	CPRINTK0("ctxt->src.addr.mem = %#lx\n", ctxt->src.addr.mem);
	CPRINTK0("ctxt->src.addr.reg = %#lx\n", ctxt->src.addr.reg);
	CPRINTK0("ctxt->src.val = %#lx\n", ctxt->src.val);
	CPRINTK0("ctxt->src.bytes = %#lx\n", ctxt->src.bytes);
	
	CPRINTK0("ctxt->src2.addr.mem = %#lx\n", ctxt->src2.addr.mem);
	CPRINTK0("ctxt->src2.addr.reg = %#lx\n", ctxt->src2.addr.reg);
	CPRINTK0("ctxt->src2.val = %#lx\n", ctxt->src2.val);
	CPRINTK0("ctxt->src2.bytes = %#lx\n", ctxt->src2.bytes);

	CPRINTK0("ctxt->dst.addr.mem = %#lx\n", ctxt->dst.addr.mem);
	CPRINTK0("ctxt->dst.addr.reg = %#lx\n", ctxt->dst.addr.reg);
	CPRINTK0("ctxt->dst.val = %#lx\n", ctxt->dst.val);
	CPRINTK0("ctxt->dst.bytes = %#lx\n", ctxt->dst.bytes);

	CPRINTK0("after regs->ip = %#lx\n", regs->ip);
	CPRINTK0("after ctxt->eip = %#lx\n", ctxt->eip);
	CPRINTK0("after ctxt->_eip = %#lx\n", ctxt->_eip);

	if (ctxt->src.bytes <= 0 || ctxt->dst.bytes <= 0) {
		PRINTK_ERR("Error: size 0!\n");
		return -EINVAL;
		
	}
	
	num_bytes = (ctxt->src.bytes <= ctxt->dst.bytes)
				? ctxt->src.bytes : ctxt->dst.bytes;
	CPRINTK0("num_bytes = %ld\n", num_bytes);

	if (write == 0 && ctxt->src.type == OP_MEM && ctxt->dst.type == OP_REG) {
		if (atype == ACCESS_MMIO) {
			success = vgt_emulate_read(vgt, (uint64_t) ctxt->src.addr.reg,
						   (void *) &val, ctxt->src.bytes);
		} else { /* ACCESS_PCI_CONFIG */
			success = vgt_emulate_cfg_read(vgt,
				(unsigned int) (((unsigned long) ctxt->src.addr.reg) - vgt->pci_config_base_addr),
				(void *) &val, ctxt->src.bytes);
		}
		memcpy(ctxt->dst.addr.reg, &val, ctxt->dst.bytes);
	} else if (write == 1 && ctxt->src.type == OP_REG && ctxt->dst.type == OP_MEM) {

		if (atype == ACCESS_MMIO) {
			success = vgt_emulate_write(vgt, (uint64_t) ctxt->dst.addr.reg,
						   &ctxt->src.val, ctxt->src.bytes);
		} else {
			success = vgt_emulate_cfg_write(vgt,
				(unsigned int) (((unsigned long) ctxt->dst.addr.reg) - vgt->pci_config_base_addr),
				&ctxt->src.val, ctxt->src.bytes);
		}
	} else if (write == 1 && (ctxt->src.type == OP_IMM ||
		   ctxt->src.type == OP_XMM) && ctxt->dst.type == OP_MEM) {
		if (atype == ACCESS_MMIO) {
			success = vgt_emulate_write(vgt, (uint64_t) ctxt->dst.addr.reg,
						   &ctxt->src.val, ctxt->src.bytes);
		} else {
			success = vgt_emulate_cfg_write(vgt,
				(unsigned int) (((unsigned long) ctxt->dst.addr.reg) - vgt->pci_config_base_addr),
				&ctxt->src.val, ctxt->src.bytes);
		}
	} else {
		PRINTK_ERR("Error: unexpected case\n");
	}

	CPRINTK0("[7]: success = %d\n", success);
	if (!success)
		return -EINVAL;

        regs->ax = ctxt->_regs[VCPU_REGS_RAX];
        regs->cx = ctxt->_regs[VCPU_REGS_RCX];
        regs->dx = ctxt->_regs[VCPU_REGS_RDX];
        regs->bx = ctxt->_regs[VCPU_REGS_RBX];
        regs->sp = ctxt->_regs[VCPU_REGS_RSP];
        regs->bp = ctxt->_regs[VCPU_REGS_RBP];
        regs->si = ctxt->_regs[VCPU_REGS_RSI];
        regs->di = ctxt->_regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
        regs->r8 = ctxt->_regs[VCPU_REGS_R8];
        regs->r9 = ctxt->_regs[VCPU_REGS_R9];
        regs->r10 = ctxt->_regs[VCPU_REGS_R10];
        regs->r11 = ctxt->_regs[VCPU_REGS_R11];
        regs->r12 = ctxt->_regs[VCPU_REGS_R12];
        regs->r13 = ctxt->_regs[VCPU_REGS_R13];
        regs->r14 = ctxt->_regs[VCPU_REGS_R14];
        regs->r15 = ctxt->_regs[VCPU_REGS_R15];
#endif

	regs->ip = ctxt->_eip;
	
	return 0x2;
}

static int is_vgt_local_addr(unsigned long addr, struct vm_area_struct *vma,
			     int is_user_addr, unsigned long error_code,
			     enum access_type *atype)
{
	/*
	 * We return as quickly as possible for kernel faults.
	 */
	if (!is_user_addr)
		return 0;

	if (!vma || (vma->emulated_range != HAS_EMULATED_RANGE))
		return 0; 

	if (is_in_emulated_range(vma, addr, atype)) {
		CPRINTK0("[1]: vgt local %s address detected\n",
				(*atype == ACCESS_MMIO) ? "MMIO" : "PCI config"); 
		return 1;
	}

	return 0;

}

/* value not important for x86 */
#define VM_FAULT_BADACCESS      0x020000

int _vgt_local_access_check(unsigned long address, unsigned long error_code,
			   struct vm_area_struct *vma, int is_user_addr,
			   struct pt_regs *regs)
{
	int write = 0, ret;
	bool found = false;
	enum access_type atype;
	
	found = is_vgt_local_addr(address, vma, is_user_addr,
						error_code, &atype);
		
	if (!found){
		goto err_out;
	}

	if (error_code & PF_WRITE)
		write = 1;	

	ret = vgt_local_emulate_mem_access(regs, write, vma, atype);

	return ret;

err_out:
	return VM_FAULT_BADACCESS; 
}

int i915_gem_pinpages_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file)
{
	struct drm_i915_gem_pinpages *args = data;
	int ret_num, ret, i;
	struct page **pages = NULL;
	pte_t *ptep;

	switch (args->pin) {
	case I915_PINPAGES_PIN:
	{
		pages = kmalloc(args->num_pages * sizeof(*pages), GFP_KERNEL);
		if (!pages) {
			PRINTK_ERR("Error: could not allocate memory for pages array\n");
			return -ENOMEM;
		}
		down_read(&(current->mm->mmap_sem));
		/* Note: it is important to pass the pages array, otherwise it would
		 * err when killing the process for bad pages.
		 */
		ret_num = get_user_pages(NULL, current->mm, args->start_page << PAGE_SHIFT,
							args->num_pages, 1, 1, pages, NULL);
		up_read(&current->mm->mmap_sem);
		if (ret_num != args->num_pages) {
			PRINTK_ERR("Error: get_user_pages failed. ret_num = %d, start_page = %#lx, "
				   "num_pages = %#lx, pin = %d\n", ret_num, (unsigned long)
				   args->start_page, (unsigned long) args->num_pages, args->pin);
			/* Note: this cond is unnecessary since it will be checked in the for loop.
			 * I'll keep it here for better clarity.
			 */
			if (ret_num) { /* negative or 0 ret_num means no pages were pinned */
				for (i = 0; i < ret_num; i++)
					put_page(pages[i]);
			}
			kfree(pages);
			return -EFAULT;
		}

		/* This wasn't really done since dma_map_page doesn't do anything.
		 * It ends up calling swiotlb_map_page(), which doesn't do anything.
		 */
		kfree(pages);

		return 0;
	}
	case I915_PINPAGES_UNPIN:
	{
		ret = 0;
		for (i = 0; i < args->num_pages; i++) {
			ptep = walk_page_tables((args->start_page + i) << PAGE_SHIFT, current->mm);
			if (ptep == NULL) {
				PRINTK_ERR("Error: ptep is NULL\n");
				ret = -EFAULT;
			}
			put_page(pte_page(*ptep));
		}
		return ret;
	}
	default:
		PRINTK_ERR("Error: invalid input, args->pin = %d\n", args->pin);
		return -EINVAL;
	}
}

