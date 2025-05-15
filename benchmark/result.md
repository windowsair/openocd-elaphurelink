# Overview

Version:

```
Open On-Chip Debugger 0.12.0+dev-01812-gcd9e64a25-dirty (2025-05-11-07:45)
```

Target: STM32F407VGT6
Interface:

- elaphureLink (esp32s3) at 26MHz
- ST-LINK v3 at 24MHz
- MCU-LINK PRO (CMSIS-DAP) at 24MHz

Test with flash write and SRAM write.

# Result

## elaphureLink

Flash:

```bash
> flash erase_address 0x08000000 0x100000
device id = 0x101f6413
flash size = 1024 KiB
erased address 0x08000000 (length 1048576) in 15.397699s (66.503 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.258805s (110.315 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.476573s (66.165 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.282860s (110.029 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.393653s (66.521 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.399295s (108.666 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.517172s (65.991 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.269589s (110.187 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.424034s (66.390 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.252782s (110.387 KiB/s)
```

SRAM:

```bash
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.418566s (303.025 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.496029s (255.703 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.404310s (313.710 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.417978s (303.451 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.464393s (273.122 KiB/s)
```


## ST-LINK v3

Flash:

```bash
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.380910s (66.576 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.130563s (111.865 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.348498s (66.717 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.129534s (111.877 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.373768s (66.607 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.129833s (111.874 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.263114s (67.090 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.172208s (111.357 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.365437s (66.643 KiB/s)
> flash write_image  /mnt/k/flash_test.bin  0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.136536s (111.791 KiB/s)
```

SRAM:

```bash
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.137539s (922.182 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.163732s (774.656 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.141831s (894.275 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.138622s (914.977 KiB/s)
> load_image /mnt/k/sram_test.bin 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.140405s (903.358 KiB/s)
```

## MCU-LINK PRO (CMSIS-DAP)

Flash:

```bash
> flash erase_address 0x08000000 0x100000
device id = 0x101f6413
flash size = 1024 KiB
erased address 0x08000000 (length 1048576) in 15.292959s (66.959 KiB/s)
> flash write_image  /mnt/k/flash_test.bin 0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.147860s (111.653 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.216081s (67.297 KiB/s)
> flash write_image  /mnt/k/flash_test.bin 0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.148766s (111.642 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.238446s (67.198 KiB/s)
> flash write_image  /mnt/k/flash_test.bin 0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.142270s (111.721 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.244977s (67.170 KiB/s)
> flash write_image  /mnt/k/flash_test.bin 0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.147615s (111.656 KiB/s)
> flash erase_address 0x08000000 0x100000
erased address 0x08000000 (length 1048576) in 15.249975s (67.148 KiB/s)
> flash write_image  /mnt/k/flash_test.bin 0x08000000
wrote 1045900 bytes from file /mnt/k/flash_test.bin in 9.148362s (111.647 KiB/s)
```

SRAM:

```bash
> load_image k:/Illustration/80501433_p1.jpg 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.178102s (712.153 KiB/s)
> load_image k:/Illustration/80501433_p1.jpg 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.178170s (711.882 KiB/s)
> load_image k:/Illustration/80501433_p1.jpg 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.178264s (711.506 KiB/s)
> load_image k:/Illustration/80501433_p1.jpg 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.177960s (712.722 KiB/s)
> load_image k:/Illustration/80501433_p1.jpg 0x20000000
129880 bytes written at address 0x20000000
downloaded 129880 bytes in 0.177973s (712.670 KiB/s)
```
