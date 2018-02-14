make -j8 && make modules_install
mkinitramfs -o /boot/initrd.img-4.2.0 -v 4.2.0-rc8-vgt+
cp arch/x86/boot/bzImage /boot/vmlinuz-4.2.0
cp vgt.rules /etc/udev/rules.d
chmod a+x vgt_mgr
cp vgt_mgr /usr/bin
