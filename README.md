# Cathago-Talenlio

A comprehensive document scanning platform with text matching capabilities and built-in credit system.

## Overview

Cathago-Talenlio is a self-contained document scanning and matching system built with Node.js and Express. The platform features a custom text matching algorithm using Levenshtein distance and word frequency analysis to identify similar documents.

Each user has a daily limit of 20 free scans, with the ability to request additional credits for more scanning capacity.

## Features

- **Document Scanning**: Upload and process document images
- **Text Matching**: Proprietary algorithm for identifying similar documents
- **User Authentication**: Secure session-based authentication
- **Credit System**: Free daily scans with additional credit requests
- **Admin Dashboard**: Complete user management and analytics

## Tech Stack

- **Backend**: Node.js, Express
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Session-based with hashed passwords
- **Database**: SQLite
- **Text Analysis**: Custom algorithm using Levenshtein distance and word frequency

## Video


https://github.com/user-attachments/assets/055ed0c6-4660-448b-9c17-b6b62427b9c4

## Screenshots

### User Authentication

#### Sign Up Page
![Sign Up Page](https://github.com/user-attachments/assets/7127567b-fff7-476d-9bd8-55a4e12db6f8)

#### Login Page
![Login Page](https://github.com/user-attachments/assets/7c4534b5-c5f1-4aff-8191-1716fc79a166)

### Main Application

#### Dashboard
![Dashboard](https://github.com/user-attachments/assets/0ef2f8c4-0def-4ddc-b50d-54f94cf7e983)

#### Scan Results
![Scan Results](https://github.com/user-attachments/assets/4e5d6153-886f-4de5-87df-76774aa6b4dd)

### Admin Panel

#### User Management
![User Management](https://github.com/user-attachments/assets/9ff9b51b-7148-4191-938a-a894882257fa)

#### Credit Requests
![Credit Requests](https://github.com/user-attachments/assets/671eb53d-b971-44dc-aa1f-3872f0156cf5)

#### Analytics Dashboard
![Analytics Dashboard](https://github.com/user-attachments/assets/c8abdb6f-fef5-4a01-affe-9195b61a77df)

## Installation

```bash
# Clone the repository
git clone https://github.com/sakkurthi-sashank/cathago-talenlio.git

# Navigate to project directory
cd cathago-talenlio

# Install dependencies
npm install

# Start the application
npm run start
```

## Usage

1. Create an account or log in
2. Upload documents for scanning
3. View matching results and analysis
4. Monitor your remaining daily credits
5. Request additional credits as needed

## Admin Features

- User account management
- Credit request processing
- Usage analytics and reporting
- System configuration
