# Blowfish-PI: A Salted State POC

## 🐟 Project Overview

**Blowfish-PI** is a Proof of Concept (POC) exploring a modified version of the Blowfish symmetric-key block cipher. While standard Blowfish uses fixed hexadecimal digits of $\pi$ to initialize its internal P-arrays and S-boxes, this implementation introduces a **salt-based initialization**—a technique inspired by the **bcrypt** hashing algorithm.

This project consists of a high-performance **C++ core** and a **Node.js Addon** wrapper, allowing the salt-heavy computation to be offloaded from the JavaScript event loop to native code.

---

## 🧠 The Concept

### The Standard Blowfish Base

Blowfish is known for its intensive "sub-key" generation. It uses:

* An 18-entry **P-array** (Permutation array).
* Four 256-entry **S-boxes** (Substitution boxes).

In the original specification, these are initialized using the fractional part of $\pi$.

### The "Bcrypt" Twist

In this POC, we treat the initialization of these arrays as a dynamic process. Instead of using a static $\pi$ constant, we incorporate a **salt**.

The salt acts as a modifier during the sub-key expansion phase. By iterating over the key expansion multiple times with the salt, we increase the computational cost of the setup, making the algorithm more resistant to brute-force attacks (much like how `bcrypt` uses the Blowfish `Eksblowfish` variant to slow down attackers).

---

## 🏗️ Architecture

The project is split into two primary layers:

### 1. The C++ Core

This is where the actual bit-shuffling happens. It handles:

* **Key Expansion:** Expanding the user-provided key and salt into the P-arrays.
* **Feistel Network:** The 16-round structure used for the encryption/decryption cycles.
* **Memory Management:** Efficient allocation for the S-box lookups.

### 2. The Node.js Addon (N-API)

To make this usable in a modern web environment, a C++ wrapper is used to bridge the gap between the C++ logic and JavaScript.

* **Data Marshalling:** Converting JavaScript Strings/Buffers into C++ `uint8_t` arrays.
* **Asynchronous Execution:** Ensuring that heavy encryption tasks don't block the Node.js main thread.

---

## 🛠️ Key Components

| Component | Responsibility |
| --- | --- |
| **P-Array** | 18 subkeys derived from $\pi$ and modified by the salt. |
| **S-Boxes** | Four tables used for non-linear substitution during rounds. |
| **Salt** | A random value that ensures even identical keys result in different P-array states. |
| **XOR Expansion** | The process where $P_i = P_i \oplus \text{Key\_Part}$ happens iteratively. |

---

## 📈 Future Goals

* Implement **Cost Factors**: Allowing the user to define the number of iteration rounds for the key expansion.
* **Parallelization**: Using C++ threads to process multiple blocks simultaneously.
* **WASM Support**: Compiling the core logic to WebAssembly for browser-side experimentation.

---