
# **DES File Crypto — Golden Theme Terminal UI**

A **terminal-based file encryption and decryption tool** using **DES** with a **fancy ncurses UI**. Perfect for learning file encryption in C while enjoying animated visuals.

## **Features**

* **Encrypt / Decrypt files** with 8-character DES keys.
* **Animated terminal UI** with:

  * Moving **golden title**
  * **Shooting stars** background
  * **Real-time progress bar**
  * **Clock display**
* **Theme toggle**: switch between golden and alternate color schemes.
* **Status messages and sound alerts** for success/error.
* Uses **OpenSSL** for cryptography and **ncurses** for terminal graphics.

## **Installation / Compilation**

```bash
sudo apt install libncurses5-dev libssl-dev
gcc des_ui_golden_fixed.c -o desfile -lcrypto -lncurses
./desfile
```

## **Usage**

* Select **Encrypt** or **Decrypt** from the menu.
* Enter the **file path** and **8-character key**.
* Watch the **progress bar** as the file is processed.
* Toggle **theme** for visual preference.

## **Purpose**

* Educational tool to demonstrate **file encryption in C**.
* Fun **terminal-based UI experience** for learning ncurses animations.
