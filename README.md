# ESSDS Scheme

ESSDS (Efficient and Scalable Secure Data Sharing) is a secure data-sharing framework designed for Internet of Vehicles (IoV) systems. It enables Service Providers (SPs) to securely share data with a large number of subscriber vehicles while providing confidentiality, integrity, authentication, and scalable group-based data distribution.

The framework is designed to support efficient data sharing in large-scale IoV environments, where a service provider may need to distribute data securely to many authorized vehicles.

## Requirements

Before compiling and running the ESSDS demo, make sure the following dependencies are installed on your system:

- **OpenSSL**
- **RELIC Toolkit**

Both libraries should be built and installed from their official source repositories.

### Recommended Environment

The demo has been tested in a Linux environment. Make sure that the following tools are also available:

- CMake
- GNU Make
- GCC/G++ compiler
- Git

You can verify the availability of the required build tools using:

```bash
gcc --version
g++ --version
cmake --version
make --version
```

## Building the Demo

After installing the required dependencies, follow the steps below to compile the ESSDS framework.

### 1. Clone the Repository

Clone the ESSDS repository and navigate to its root directory:

```bash
git clone https://github.com/Mahmoud-Abdelsatar/ESSDS.git
cd ESSDS
```

Replace `https://github.com/Mahmoud-Abdelsatar/ESSDS.git` and `ESSDS` with the appropriate repository URL and directory name.

### 2. Create the Build Directory

Create a dedicated directory for the build files:

```bash
mkdir build
```

### 3. Enter the Build Directory

```bash
cd build
```

### 4. Configure the Project

Run CMake to configure the project:

```bash
cmake ..
```

CMake will detect the required libraries and generate the appropriate build configuration.

### 5. Compile the Project

Build the ESSDS demo using:

```bash
make
```

After a successful compilation, the executable files for the different entities will be generated in the `bin` directory:

- `ta_demo` — Trusted Authority (TA)
- `sp_demo` — Service Provider (SP)
- `edge_demo` — Edge Server
- `vehicle_demo` — Subscriber Vehicle

## Running the Demo

After successfully compiling the project, navigate to the `bin` directory:

```bash
cd bin
```

The demo consists of four executable programs representing the main entities in the ESSDS architecture:

```text
ta_demo
sp_demo
edge_demo
vehicle_demo
```

Run the required executable, for example:

```bash
./ta_demo
```

The program will display the available operations and instructions on the terminal. Select the desired operation by entering the corresponding option.

Similarly, the other components can be executed using:

```bash
./sp_demo
./edge_demo
./vehicle_demo
```

### Important Note

The demo currently supports **one operation at a time**. Follow the instructions displayed by each executable and select the required operation from the available options.

## Demo Components

The ESSDS demo represents the following entities:

| Component | Description |
|---|---|
| **TA** | Trusted Authority responsible for system initialization and management of cryptographic parameters and credentials. |
| **SP** | Service Provider responsible for generating and securely sharing data with authorized subscriber vehicles. |
| **Edge Server** | Edge infrastructure that assists with data distribution and communication between the service provider and vehicles. |
| **Vehicle** | Subscriber vehicle that receives and accesses authorized data from the service provider. |

