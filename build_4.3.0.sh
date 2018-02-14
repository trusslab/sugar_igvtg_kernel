cp config-4.3.0-host .config
make -j16 && make modules_install
mkinitramfs -o /boot/initrd.img-4.3.0 -v 4.3.0-rc6-vgt+
cp arch/x86/boot/bzImage /boot/vmlinuz-4.3.0
cp vgt.rules /etc/udev/rules.d
chmod a+x vgt_mgr
cp vgt_mgr /usr/bin
sync
