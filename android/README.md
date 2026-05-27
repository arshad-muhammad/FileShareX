# 📱 FileShareX - Native Android Application (Capacitor)

This directory contains the native **Android Studio** project workspace for FileShareX. It encapsulates the compiled Next.js web build into a native mobile app container using **Ionic Capacitor**.

---

## 🛠️ Technology Stack & Structure

- **Mobile Wrapper**: Ionic Capacitor 6
- **Build System**: Android Gradle Wrapper (target compiled SDK Level 35)
- **Target OS Compatibility**: Android 7.0 (API Level 23) up to Android 15 (API Level 35)

### 📂 Directory Layout
```
android/
├── app/
│   └── src/
│       └── main/
│           ├── AndroidManifest.xml   <-- Declare permissions (Camera, Mic, Network, Alerts)
│           ├── java/                 <-- Native Java MainActivity triggers
│           └── res/
│               └── xml/
│                   └── network_security_config.xml <-- LAN private subnets whitelists
├── gradle/                           <-- Gradle system wraps
├── variables.gradle                  <-- Declare targetSdkVersion = 35 and minSdkVersion = 23
└── build.gradle                      <-- Top-level Gradle configs
```

---

## 🔒 Google Play Store Compliance

This application compiles targeting **API Level 35 (Android 15)** to satisfy all Play Store requirements (Target SDK 34+):
* **Active Permissions**: Request Microphone and Camera streams for WebRTC calling, and Notification permissions for alerts on inbound transfers.
* **WiFi Auto-Discovery Beacons**: Declares `CHANGE_WIFI_MULTICAST_STATE` to discover local peers over the network.
* **Subnet Security Configuration**: Whitelists unencrypted traffic strictly to private Wi-Fi ranges (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) to enable LAN connections without compromising security on public remote HTTP domains.

---

## 🚀 Commands & Compilation

Run the following commands directly inside this directory (or run their root wrappers):

### 1. Sync Latest Web Builds
Sync your compiled website resources (`/website/out`) into Capacitor native folder assets:
```bash
npx cap sync
```

### 2. Compile APK (Android Studio Pathway)
Because modern systems run **Java 25** (`25.0.2`), running Gradle builds directly from the command line wrapper will throw incompatible major version 69 bytecode errors (since Gradle 8.x Groovy does not support Java 25 yet).

**To build smoothly**:
1. Open **Android Studio**.
2. Select **Open** and choose the **`android`** folder inside the `FileShareX` project directory.
3. Once Android Studio syncs Gradle utilizing its own bundled compatible JVM (JDK 17 or JDK 21), go to **Build** > **Build Bundle(s) / APK(s)** > **Build APK(s)**.
4. Locate the compiled debug package **`app-debug.apk`** in:
   `android/app/build/outputs/apk/debug/app-debug.apk`
