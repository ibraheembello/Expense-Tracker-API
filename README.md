# Expense Tracker API

Project based on: [roadmap.sh Expense Tracker API Project](https://roadmap.sh/projects/expense-tracker-api)

## Description

A RESTful API for tracking personal expenses with user authentication and filtering capabilities.

## Features

- User authentication (signup/login) with JWT
- CRUD operations for expenses
- Expense categorization
- Date-based filtering:
  - Past week
  - Past month
  - Last 3 months
  - Custom date range

## Tech Stack

- Node.js
- Express.js
- MongoDB
- JWT for authentication
- Express Validator for input validation

## Setup

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. Create a .env file with the following variables:

```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
PORT=3000
```

4. Start the server:

```bash
node "Expense Tracker API.js"
```

## API Endpoints

### Authentication

- POST `/signup` - Register a new user
- POST `/login` - Login user

### Expenses

- GET `/expenses` - Get all expenses (with optional filters)
- POST `/expenses` - Create new expense
- PUT `/expenses/:id` - Update expense
- DELETE `/expenses/:id` - Delete expense

### Filter Parameters

The `/expenses` endpoint accepts the following query parameters:

- `filter`: week | month | threemonths | custom
- `startDate`: ISO date (required for custom filter)
- `endDate`: ISO date (required for custom filter)

## Expense Categories

- Groceries
- Leisure
- Electronics
- Utilities
- Clothing
- Health
- Others

## Request Examples

### Create Expense

```json
POST /expenses
{
  "amount": 50.00,
  "category": "Groceries",
  "description": "Weekly groceries"
}
```

### Filter Expenses

```
GET /expenses?filter=week
GET /expenses?filter=custom&startDate=2024-01-01&endDate=2024-01-31
```

## Testing

Run tests using:

```bash
npm test
```

## Error Handling

The API includes comprehensive error handling for:

- Validation errors
- Authentication errors
- Database errors
- Invalid requests

## Security Features

- Password hashing
- JWT token expiration
- Input validation and sanitization
- Protected routes with authentication middleware
