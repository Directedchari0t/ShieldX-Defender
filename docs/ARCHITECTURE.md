# ShieldX-Defender Architecture

## Overview
ShieldX-Defender is built with a modular, layered architecture that enables real-time file monitoring and malware detection. The system comprises three main components:

1. **Monitoring Layer** - Watches directories for file changes
2. **Detection Layer** - Performs malware analysis using multiple techniques
3. **Presentation Layer** - Provides web interface for interaction

## Component Diagram

```mermaid
graph TD
    A[File System] --> B(File Monitor)
    B --> C{File Event}
    C -->|Created/Modified| D[Scanner]
    D --> E[YARA Engine]
    D --> F[Hash Check]
    D --> G[File Type Analysis]
    E --> H[Detection Result]
    F --> H
    G --> H
    H --> I[(Database)]
    H --> J[Alert System]
    I --> K[Web Dashboard]




