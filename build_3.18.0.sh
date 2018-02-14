make -j8 && make modules_install
mkinitramfs -o /boot/initrd.img-3.18.0 -v 3.18.0-rc7-vgt-2015q3+
cp arch/x86/boot/bzImage /boot/vmlinuz-3.18.0
cp vgt.rules /etc/udev/rules.d
chmod a+x vgt_mgr
cp vgt_mgr /usr/bin
