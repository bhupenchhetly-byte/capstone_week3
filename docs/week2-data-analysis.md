# Capstone B - Week 2 Data Analysis

## 1. Introduction

This document explains how data is managed in our Admin Dashboard Panel project. It includes the Data Inventory, Data Flow Diagram, and Data Risk Analysis.

## 2. Data Inventory

| Data Type | Description | Example | Storage |
|---|---|---|---|
| User Data | Information about registered users | Name, email, user ID | Database |
| Login Data | Information used for authentication | Email, password hash | Database |
| Product Data | Information about products | Product name, price, quantity | Database |
| Order Data | Information about customer orders | Order ID, date, status | Database |
| Admin Data | Information about administrators | Admin ID, role | Database |
| Dashboard Data | Information displayed on the dashboard | Sales, users, orders | Database |

## 3. Data Flow Diagram

The Admin Dashboard Panel follows this general data flow:

User/Admin
↓
Login Page
↓
Authentication System
↓
Backend API
↓
Database
↓
Backend API
↓
Admin Dashboard
↓
Reports and Information

The diagram shows how information moves between users, the application, APIs and the database.

## 4. Data Risk Analysis

| Data | Risk | Impact | Control |
|---|---|---|---|
| User Data | Unauthorised access | High | Authentication and access control |
| Login Data | Password exposure | High | Password hashing and secure authentication |
| Product Data | Unauthorised modification | Medium | Admin permissions |
| Order Data | Data loss or incorrect changes | High | Database backup and validation |
| Admin Data | Privilege misuse | High | Role-based access control |
| Dashboard Data | Incorrect information | Medium | Data validation and testing |


## 5. Conclusion

The Data Inventory identifies the main types of data used by the Admin Dashboard Panel. The Data Flow Diagram explains how data moves through the system, while the Data Risk Analysis identifies potential risks and suitable controls. These activities help the development team plan how project data should be stored, processed and protected.
