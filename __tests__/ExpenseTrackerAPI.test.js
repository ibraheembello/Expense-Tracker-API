const request = require('supertest');
const app = require('../app'); // Adjust the path as necessary

describe('Expense Tracker API', () => {
    test('GET /expenses should return a list of expenses', async () => {
        const response = await request(app).get('/expenses');
        expect(response.statusCode).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
    });

    test('POST /expenses should create a new expense', async () => {
        const newExpense = { description: 'Test Expense', amount: 100 };
        const response = await request(app).post('/expenses').send(newExpense);
        expect(response.statusCode).toBe(201);
        expect(response.body.description).toBe(newExpense.description);
        expect(response.body.amount).toBe(newExpense.amount);
    });
});