import * as chai from 'chai';
import chaiHttp from 'chai-http';
import jwt from 'jsonwebtoken';
import { app } from '../server.js';

// Use Chai HTTP
chai.use(chaiHttp);
const { expect } = chai;

describe('JWKS Server Tests with Rate Limiting and Logs', () => {
  let validToken;
  let expiredToken;

  it('should return 200 for GET /.well-known/jwks.json', (done) => {
    chai
      .request(app)
      .get('/.well-known/jwks.json')
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res.body).to.have.property('keys');
        expect(res.body.keys).to.be.an('array');
        done();
      });
  });

  it('should generate a valid JWT on POST /auth and log the request', (done) => {
    chai
      .request(app)
      .post('/auth')
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res.text).to.be.a('string');
        validToken = res.text;

        const decoded = jwt.decode(validToken, { complete: true });
        expect(decoded.payload.exp).to.be.greaterThan(Math.floor(Date.now() / 1000));

        done();
      });
  });

  it('should generate an expired JWT on POST /auth with ?expired=true', (done) => {
    chai
      .request(app)
      .post('/auth?expired=true')
      .end((err, res) => {
        expect(res).to.have.status(200);
        expect(res.text).to.be.a('string');
        expiredToken = res.text;

        const decoded = jwt.decode(expiredToken, { complete: true });
        expect(decoded.payload.exp).to.be.lessThan(Math.floor(Date.now() / 1000));

        done();
      });
  });

  it('should return 429 Too Many Requests after exceeding the rate limit', async () => {
    const requests = [];
    for (let i = 0; i < 12; i++) {
      requests.push(
        chai
          .request(app)
          .post('/auth')
          .then((res) => res)
          .catch((err) => err.response)
      );
    }

    const results = await Promise.all(requests);

    const successResponses = results.filter((res) => res.status === 200);
    const tooManyRequestsResponses = results.filter((res) => res.status === 429);

    expect(successResponses.length).to.be.lessThanOrEqual(10);
    expect(tooManyRequestsResponses.length).to.be.greaterThan(0);
    expect(tooManyRequestsResponses[0].text).to.equal('Too Many Requests');
  });

  it('should return 405 for invalid method on /.well-known/jwks.json', (done) => {
    chai
      .request(app)
      .post('/.well-known/jwks.json')
      .end((err, res) => {
        expect(res).to.have.status(404);
        done();
      });
  });

  it('should return 400 for registration without required fields', (done) => {
    chai
      .request(app)
      .post('/register')
      .send({ username: 'testUser' })
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.text).to.equal('Username and email are required.');
        done();
      });
  });

  it('should return 201 and a password for valid registration', (done) => {
    chai
      .request(app)
      .post('/register')
      .send({ username: 'testUser', email: 'test@example.com' })
      .end((err, res) => {
        expect(res).to.have.status(201);
        expect(res.body).to.have.property('password');
        expect(res.body.password).to.be.a('string');
        done();
      });
  });

  it('should return 500 for internal server errors', async () => {
    const originalDBRun = app.locals.db.run; // Mocking `db.run` for this test
    app.locals.db.run = async () => {
      throw new Error('Simulated database error');
    };

    try {
      const res = await chai.request(app).post('/auth');
      expect(res).to.have.status(500);
      expect(res.text).to.equal('Internal Server Error');
    } finally {
      app.locals.db.run = originalDBRun; // Restore original function
    }
  });
});
