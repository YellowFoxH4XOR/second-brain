# Deel Interview Prep — Complete Revision Guide

---

## PART 1: SQL & DATABASES

### 1. Tables, Keys & DDL

**Core concepts:**
- **Primary key** — unique ID for every row. Always use `id INT`, never a name.
- **Foreign key** — references another table's primary key. Links tables together.
- **NOT NULL** — column must have a value.
- **DECIMAL(10,2)** — always use for money, never INT.

**Schema to know:**
```sql
CREATE TABLE companies (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  address VARCHAR(255)
);

CREATE TABLE employees (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  salary DECIMAL(10,2) NOT NULL,
  company_id INT NOT NULL,
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE payments (
  id INT PRIMARY KEY AUTO_INCREMENT,
  amount DECIMAL(10,2) NOT NULL CHECK (amount > 0),
  status VARCHAR(20),
  created_at DATETIME,
  employee_id INT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id)
);
```

---

### 2. Indexes

- Add indexes on columns you frequently **search or filter** on.
- **Read-heavy tables** → use indexes. **Write-heavy tables** → skip them.
- Indexes speed up reads but slow down writes.
- Columns with few distinct values (like `status`) → poor index candidates alone.

**Composite index — column order matters:**
```sql
-- For: WHERE status = 'pending' AND created_at > '2026-01-01'
-- Equality conditions first, range conditions last
CREATE INDEX idx_status_created ON payments(status, created_at);
```

**EXPLAIN output:**
- **Seq Scan** → scanning every row. Bad on large tables. Fix with an index.
- **Index Scan** → jumping directly to matching rows. Good.

**Never use SELECT * on large tables:**
```sql
-- Bad
SELECT * FROM payments WHERE created_at > '2026-01-01';

-- Good
SELECT id, employee_id, amount FROM payments WHERE created_at > '2026-01-01';
```

---

### 3. JOINs

**Mental model:** A JOIN stitches two tables together sideways — adds columns from the right table onto the left table's rows.

| JOIN type | What it returns |
|-----------|----------------|
| INNER JOIN | Only rows matching in both tables |
| LEFT JOIN | All left rows + matching right rows (NULL if no match) |
| RIGHT JOIN | All right rows + matching left rows (rare) |

**ON condition rule — always match foreign key to primary key:**
```sql
ON employees.company_id = companies.id
```

**Multi-table JOIN:**
```sql
SELECT employees.name, companies.name, payments.amount
FROM employees
INNER JOIN companies ON employees.company_id = companies.id
INNER JOIN payments ON payments.employee_id = employees.id;
```

**LEFT JOIN trap — WHERE vs ON:**
```sql
-- WHERE kills the LEFT JOIN effect (acts like INNER JOIN)
SELECT e.name, d.name FROM employees e
LEFT JOIN departments d ON e.department_id = d.id
WHERE d.name = 'Engineering';

-- ON preserves LEFT JOIN — non-Engineering employees appear with NULL
SELECT e.name, d.name FROM employees e
LEFT JOIN departments d
  ON e.department_id = d.id AND d.name = 'Engineering';
```

---

### 4. GROUP BY & Aggregates

**Aggregate functions:** SUM, COUNT, AVG, MAX, MIN

**Rules:**
- GROUP BY must include all non-aggregated SELECT columns
- WHERE filters rows before grouping
- HAVING filters groups after grouping

**Query execution order:**
```
FROM → JOIN → WHERE → GROUP BY → HAVING → SELECT → ORDER BY
```

**Example:**
```sql
SELECT departments.name, SUM(payments.amount) AS total_payment
FROM departments
INNER JOIN employees ON employees.department_id = departments.id
INNER JOIN payments ON payments.employee_id = employees.id
WHERE payments.created_at >= '2026-01-01'
GROUP BY departments.name, departments.budget
HAVING SUM(payments.amount) > 0.5 * departments.budget
ORDER BY total_payment DESC;
```

**COUNT trap:**
- `COUNT(*)` → counts all rows including NULLs
- `COUNT(column)` → counts only non-NULL values
- `SUM(column)` on all NULLs → returns NULL, not 0

---

### 5. ACID Properties

#### A — Atomicity
All steps complete or none do. No partial transactions.

**Write-Ahead Log (WAL):**
- Records every step with BEFORE and AFTER values
- No COMMIT in log → rollback everything on restart
- Corrupted log → rollback what's readable, restore rest from backup

```sql
BEGIN TRANSACTION;
  UPDATE accounts SET balance = balance - 5000 WHERE name = 'Deel';
  UPDATE accounts SET balance = balance + 5000 WHERE name = 'Priya';
COMMIT;
```

#### C — Consistency
Database enforces rules (constraints). Invalid data is always rejected.
```sql
amount DECIMAL(10,2) NOT NULL CHECK (amount > 0)
```

#### I — Isolation
Concurrent transactions don't interfere with each other.

**Three problems:**
| Problem | What happens |
|---------|-------------|
| Dirty read | Reading uncommitted data from another transaction |
| Non-repeatable read | Same row returns different values in two reads |
| Phantom read | Same query returns different rows (new rows inserted) |

**Four isolation levels:**
| Level | Dirty read | Non-repeatable read | Phantom read |
|-------|-----------|-------------------|--------------|
| Read Uncommitted | ❌ | ❌ | ❌ |
| Read Committed | ✅ | ❌ | ❌ |
| Repeatable Read | ✅ | ✅ | ❌ |
| Serializable | ✅ | ✅ | ✅ |

**For Deel payroll → Read Committed (PostgreSQL default):**
- Dirty reads are the real risk → prevented
- Non-repeatable reads unlikely → salary changes have a cutoff date
- Phantom reads unlikely → no new employees added mid-payroll

#### D — Durability
Once committed, data survives crashes. WAL written to disk before COMMIT confirmed.

---

### 6. Locking & Concurrency

**The problem:** Two transactions reading same value, both writing → one update lost.

**Pessimistic Locking** — lock the row before touching it:
```sql
BEGIN TRANSACTION;
  SELECT * FROM accounts WHERE name = 'Priya' FOR UPDATE;
  UPDATE accounts SET balance = balance + 5000 WHERE name = 'Priya';
COMMIT;
```
Use when: conflicts are **frequent** (payroll, payments).

**Optimistic Locking** — check before writing, retry if changed.
Use when: conflicts are **rare** (profile updates).

**Deadlocks:** Two transactions waiting for each other's locks forever.
- Fix 1: Always acquire locks in the **same order**
- Fix 2: Set lock timeout → database picks a victim and rolls back

```sql
SET lock_timeout = '5s';
```

---

### 7. Performance Checklist

For any slow query:
1. Run **EXPLAIN** — look for Seq Scans
2. Add **composite index** on WHERE columns (equality first, range last)
3. Replace **SELECT *** with specific columns
4. Move date filters to **WHERE**, not HAVING
5. Use **caching** (Redis) if query runs frequently
6. Use **relative updates** not absolute: `SET balance = balance + 500` not `SET balance = 1500`

---

### 8. N+1 Problem (ORM)

```javascript
// BAD — 1 query for companies + 100 queries for employees = 101 queries
const companies = await Company.findAll({ include: [Employee] });

// GOOD — use eager loading, 1 JOIN query
const companies = await Company.findAll({
  include: [{ model: Employee, separate: false }]
});
```

---

## PART 2: NODE.JS

### 1. Core Concepts

**Single-threaded + non-blocking I/O:**
- Node has ONE main thread
- I/O work (database, files, API calls) → handed to OS, thread stays free
- CPU work (image resizing, calculations) → blocks the thread → use Worker Threads

**Async vs Parallel:**
- **Async** = single thread, non-blocking. One thread juggles many tasks.
- **Parallel** = multiple threads running simultaneously. Worker Threads, child processes.

---

### 2. Event Loop

**Before event loop:** Node reads entire file, runs all synchronous code, registers callbacks.

**Six phases:**
```
Phase 1: TIMERS        → setTimeout, setInterval callbacks
Phase 2: PENDING I/O   → deferred I/O callbacks (edge cases)
Phase 3: IDLE/PREPARE  → internal Node use only
Phase 4: POLL          → wait for and receive new I/O events (most time spent here)
Phase 5: CHECK         → setImmediate callbacks
Phase 6: CLOSE         → cleanup callbacks (socket.on('close'))
```

**Between every phase → Promises (microtasks) run first. Always.**

**Execution order:**
1. Synchronous code
2. Microtasks — Promises
3. Macrotasks — setTimeout, setImmediate

**Example:**
```javascript
console.log('1');          // sync → prints first
setTimeout(() => console.log('2'), 0);  // macrotask → prints last
Promise.resolve().then(() => console.log('3'));  // microtask → prints third
console.log('4');          // sync → prints second
// Output: 1, 4, 3, 2
```

**setTimeout vs setImmediate:**
- `setTimeout(fn, 0)` → timers phase, minimum delay
- `setImmediate(fn)` → check phase, runs after current I/O cycle
- Inside I/O callback → setImmediate always runs first

---

### 3. Promises

**Four Promise methods:**
| Method | Behaviour |
|--------|-----------|
| `Promise.all` | Waits for all. Fails fast if any one fails |
| `Promise.allSettled` | Waits for all. Returns success or failure for each |
| `Promise.race` | Returns as soon as first one finishes (success or failure) |
| `Promise.any` | Returns as soon as first one succeeds. Ignores failures |

**Sequential vs Parallel:**
```javascript
// Sequential — 3 seconds total (bad for independent calls)
const employees = await getEmployees();
const payments = await getPayments();
const companies = await getCompanies();

// Parallel — 1 second total (good)
const [employees, payments, companies] = await Promise.all([
  getEmployees(),
  getPayments(),
  getCompanies()
]);
```

**Use Promise.all** when all must succeed (payroll processing).
**Use Promise.allSettled** when partial results are okay (payslip generation).

---

### 4. async/await Error Handling

```javascript
// Always wrap in try/catch
async function processPayroll() {
  try {
    const employees = await getEmployees();
    return employees;
  } catch (err) {
    throw err; // re-throw so caller knows it failed
  }
}

// Always await or catch when calling async functions
await processPayroll();
// or
processPayroll().catch(err => console.log(err));
```

**Common mistake:** Not re-throwing in catch → function returns undefined silently.

---

### 5. ORMs (Sequelize)

**Three things ORMs give you:**
1. **Abstraction** — write JavaScript instead of raw SQL
2. **Associations** — relationships and automatic JOINs
3. **Migrations** — versioned, reversible schema changes

**Model definition:**
```javascript
const Employee = sequelize.define('Employee', {
  name: { type: DataTypes.STRING, allowNull: false },
  salary: { type: DataTypes.DECIMAL(10, 2), allowNull: false }
});
```

**Associations:**
```javascript
Company.hasMany(Employee);   // Company is the parent
Employee.belongsTo(Company); // Employee holds the foreign key (company_id)
```

**Eager loading to prevent N+1:**
```javascript
const employees = await Employee.findAll({
  include: [{ model: Company, required: true }] // required: true = INNER JOIN
});
```

**Migrations — up and down:**
```javascript
module.exports = {
  up: async (queryInterface) => {
    await queryInterface.addColumn('employees', 'department_id', {
      type: DataTypes.INTEGER
    });
  },
  down: async (queryInterface) => {
    await queryInterface.removeColumn('employees', 'department_id');
  }
};
```

---

### 6. Queues (Bull + Redis)

**Why queues?**
1. **Rate limiting** — controlled database load, no overload
2. **Load balancing** — distribute jobs across multiple workers
3. **Retry on failure** — automatic retries without extra code
4. **Job persistence** — jobs survive server crashes (stored in Redis)

**Bull example:**
```javascript
const payrollQueue = new Queue('payroll');

// Add jobs
employees.forEach(employee => {
  payrollQueue.add(
    { employeeId: employee.id },
    { attempts: 3, backoff: 2000 } // retry 3 times, wait 2s between retries
  );
});

// Process in controlled batches (10 concurrent)
payrollQueue.process(10, async (job) => {
  await processPayment(job.data.employeeId);
});
```

---

## PART 3: SYSTEM DESIGN

### Subscription Billing System

**Components:**

1. **Subscription API** — creates subscription with `auto_renew = true`, `status = 'active'`

2. **Midnight cron job** — finds expiring subscriptions:
```sql
-- Lock rows to prevent double processing
BEGIN TRANSACTION;
SELECT * FROM subscriptions
WHERE expiry_date = TODAY AND status = 'active'
FOR UPDATE;
UPDATE subscriptions SET status = 'renewing' WHERE id = ?;
COMMIT;
```

3. **Email notification** — 5 days before expiry via notification queue with retry

4. **Payment queue** — on expiry day, send jobs to Bull queue with retry

5. **Regional partitioning** — separate queues and workers per region (India, USA, Germany)

6. **Strategy pattern** — country-specific billing rules:
```javascript
const billingStrategies = {
  India: new IndiaBillingStrategy(),    // GST
  Germany: new GermanyBillingStrategy(), // VAT
  USA: new USABillingStrategy()          // no tax
};
const strategy = billingStrategies[country];
await strategy.processPayment(subscription);
```

**Idempotency:** Status flag (`active` → `renewing` → `completed`) prevents double charging.

---

### Zero Downtime Migration (Dual Write)

1. Keep old system running
2. Write to BOTH old and new systems simultaneously
3. Migrate old data in background batches
4. Verify data integrity
5. Switch reads to new system
6. Decommission old system

---

### 2am Incident Response

1. Check logs — is it one endpoint or whole service?
2. Isolate the problem
3. Check what changed — deployment? data volume? deadlocks?
4. If recent deployment → **rollback immediately**
5. Investigate root cause after system is stable

---

## PART 4: DEPLOYMENT PATTERNS

| Pattern | How it works | When to use |
|---------|-------------|-------------|
| **Blue-Green** | Two environments, switch traffic instantly | Major releases, instant rollback needed |
| **Canary** | Roll out to 1% → 5% → 100% of traffic | Testing new features safely |
| **Rolling** | Replace pods one by one, old dies when new is healthy | Standard deployments, zero downtime |
| **Feature Flags** | Toggle features on/off per user | A/B testing, gradual feature rollout |

---

## PART 5: DESIGN PATTERNS

### Singleton
One instance throughout entire application lifecycle.
```javascript
// db.js — Node module caching makes this a singleton automatically
const sequelize = new Sequelize(DATABASE_URL, { pool: { max: 10, min: 2 } });
module.exports = sequelize;
```
Use for: database connection pools, config objects.

### Factory
Creates objects without exposing creation logic. Caller says "what", factory decides "how".
```javascript
class PaymentFactory {
  static create(country) {
    const processors = {
      India: new RazorpayProcessor(),
      USA: new StripeProcessor(),
      Germany: new SEPAProcessor()
    };
    return processors[country];
  }
}
const processor = PaymentFactory.create('India');
```
Use for: payment processors, notification senders per channel.

### Strategy
Swappable algorithms. Caller explicitly picks and injects the strategy.
```javascript
class PaymentProcessor {
  constructor(strategy) { this.strategy = strategy; }
  async charge(amount) { return this.strategy.charge(amount); }
}
const processor = new PaymentProcessor(new RazorpayStrategy());
```
**Factory vs Strategy:** Factory decides which object to create. Strategy is injected by the caller.

### Observer
Objects subscribe to events and get notified when something changes.
```javascript
// Payment success event
eventEmitter.emit('payment.success', { employeeId, amount });

// Subscribers react independently
eventEmitter.on('payment.success', sendEmailConfirmation);
eventEmitter.on('payment.success', updateAccountingRecords);
eventEmitter.on('payment.success', sendSlackNotification);
```
Use for: notifications, audit logs, decoupled event handling.

### Adapter
Converts one interface into another. Bridge between incompatible systems.
```javascript
class AudioAdapter {
  constructor(videoService) { this.videoService = videoService; }
  getAudio(file) {
    const video = this.videoService.getVideo(file);
    return this.convertToAudio(video);
  }
}
```
Use for: third-party integrations, legacy system compatibility.

---

## QUICK REFERENCE — DEEL INTERVIEW ANSWERS

**Slow query?** → EXPLAIN first, look for Seq Scans, add composite index, remove SELECT *, consider caching.

**Double payments?** → Pessimistic locking (SELECT FOR UPDATE) + idempotency status flag.

**10,000 simultaneous payrolls?** → Queue (Bull) with controlled concurrency, not Promise.all.

**Which isolation level for payroll?** → Read Committed (PostgreSQL default). Prevents dirty reads, performant.

**Deadlock prevention?** → Always acquire locks in the same order across all transactions.

**Zero downtime deployment?** → Blue-green or canary deployment with feature flags.

**150 countries, different tax rules?** → Strategy pattern per country + Factory to create the right strategy.

**Scaling payroll to 10M users?** → Regional partitioning (separate queues per region), horizontal scaling.
