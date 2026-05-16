# SQL & Databases — Deel Interview Prep
## Complete Consolidation

---

## 1. Tables, Keys & DDL

### Core concepts
- **Primary key** — unique ID for every row (always use `id INT`, never a name)
- **Foreign key** — references another table's primary key (links tables together)
- **NOT NULL** — column must have a value
- **DECIMAL(10,2)** — use for money, never INT

### Schema to memorise (Deel-relevant)
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
  department_id INT NOT NULL,
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

## 2. Indexes

### When to add an index
- Column is frequently searched or filtered on
- Table is read-heavy (payments, payslips, audit logs)

### When NOT to add an index
- Column has very few distinct values (e.g. `status` with 3 values)
- Table is write-heavy (every insert/update must also update the index)

### Composite index — column order matters
```sql
-- For: WHERE status = 'pending' AND created_at > '2026-01-01'
CREATE INDEX idx_status_created ON payments(status, created_at);
```
Put the most selective column first.

### Always avoid SELECT *
```sql
-- Bad — fetches all columns on 50M rows
SELECT * FROM payments WHERE created_at > '2026-01-01';

-- Good — only fetch what you need
SELECT id, employee_id, amount FROM payments WHERE created_at > '2026-01-01';
```

### Reading EXPLAIN output
- **Seq Scan** — scanning every row. Bad on large tables. Fix with an index.
- **Index Scan** — jumping directly to matching rows. Good.

---

## 3. JOINs

### Mental model
A JOIN stitches two tables together sideways — adds columns from the right table onto the left table's rows.

| JOIN type | What it returns |
|-----------|----------------|
| INNER JOIN | Only rows that match in both tables |
| LEFT JOIN | All left table rows + matching right rows (NULL if no match) |
| RIGHT JOIN | All right table rows + matching left rows (rare) |

### Syntax
```sql
-- INNER JOIN — drop employees with no company
SELECT employees.name, companies.name
FROM employees
INNER JOIN companies ON employees.company_id = companies.id;

-- LEFT JOIN — keep all employees, even without a company
SELECT employees.name, companies.name
FROM employees
LEFT JOIN companies ON employees.company_id = companies.id;
```

### ON condition rule
Always match foreign key to primary key:
```
ON employees.company_id = companies.id
   ↑ foreign key (left)   ↑ primary key (right)
```

### Multi-table JOIN
```sql
SELECT employees.name, companies.name, payments.amount
FROM employees
INNER JOIN companies ON employees.company_id = companies.id
INNER JOIN payments ON payments.employee_id = employees.id;
```

---

## 4. GROUP BY & Aggregates

### Aggregate functions
| Function | What it does |
|----------|-------------|
| SUM(col) | Total |
| COUNT(*) | Number of rows |
| AVG(col) | Average |
| MAX(col) | Highest value |
| MIN(col) | Lowest value |

### Rules
- GROUP BY must include all non-aggregated columns in SELECT
- WHERE filters rows before grouping
- HAVING filters groups after grouping (use for aggregate conditions)

### Query execution order
```sql
FROM        -- 1. which table
JOIN        -- 2. connect tables
WHERE       -- 3. filter rows (before grouping)
GROUP BY    -- 4. collapse rows into groups
HAVING      -- 5. filter groups (after grouping)
SELECT      -- 6. calculate aggregates
ORDER BY    -- 7. sort results
```

### Example
```sql
-- Total payments per department in 2026, only departments > $50K total
SELECT 
  departments.name,
  COUNT(employees.id) AS total_emp,
  SUM(payments.amount) AS total_payment,
  AVG(employees.salary) AS avg_salary,
  departments.budget
FROM departments
INNER JOIN employees ON employees.department_id = departments.id
INNER JOIN payments ON payments.employee_id = employees.id
WHERE payments.created_at >= '2026-01-01'
GROUP BY departments.name, departments.budget
HAVING SUM(payments.amount) > 0.5 * departments.budget
ORDER BY total_payment DESC;
```

---

## 5. ACID Properties

### A — Atomicity
All steps in a transaction complete, or none do. No partial transactions.

**How:** Write-Ahead Log (WAL) records every step with BEFORE and AFTER values.
- Server crashes before COMMIT → database reads WAL → rolls back all steps
- No COMMIT in log = transaction never happened

```sql
BEGIN TRANSACTION;
  UPDATE accounts SET balance = balance - 5000 WHERE name = 'Deel';
  UPDATE accounts SET balance = balance + 5000 WHERE name = 'Priya';
COMMIT; -- both succeed or both roll back
```

### C — Consistency
The database enforces rules (constraints). Invalid data is always rejected.
```sql
amount DECIMAL(10,2) NOT NULL CHECK (amount > 0)
-- Inserting -$5000 → exception thrown, transaction rejected
```

### I — Isolation
Concurrent transactions don't interfere with each other.

**Three problems isolation levels solve:**

| Problem | What happens |
|---------|-------------|
| Dirty read | Transaction A reads uncommitted data from Transaction B |
| Non-repeatable read | Same row returns different values in two reads within one transaction |
| Phantom read | Same query returns different rows in two reads (new rows inserted) |

**Four isolation levels:**

| Level | Dirty read | Non-repeatable read | Phantom read | Performance |
|-------|-----------|-------------------|--------------|-------------|
| Read Uncommitted | ❌ Possible | ❌ Possible | ❌ Possible | Fastest |
| Read Committed | ✅ Prevented | ❌ Possible | ❌ Possible | Fast |
| Repeatable Read | ✅ Prevented | ✅ Prevented | ❌ Possible | Medium |
| Serializable | ✅ Prevented | ✅ Prevented | ✅ Prevented | Slowest |

**For Deel payroll:** Use **Read Committed** (PostgreSQL default) because:
- Dirty reads are the real risk → prevented ✓
- Non-repeatable reads unlikely → salary changes have a cutoff date ✓
- Phantom reads unlikely → no new employees added mid-payroll ✓

### D — Durability
Once committed, data survives crashes. WAL written to disk before COMMIT is confirmed.

**WAL recovery scenarios:**
- COMMIT in log → replay on restart ✓
- No COMMIT in log → roll back on restart ✓
- Log not written → transaction never existed ✓
- Disk destroyed → restore from last backup (data loss = time since last backup)

---

## 6. Locking & Concurrency

### The problem
Two transactions writing to the same row simultaneously:
- Both read balance: $1000
- Both calculate $1000 + $5000 = $6000
- Both write $6000
- Priya loses $5000

### Pessimistic Locking
Lock the row before touching it. One transaction at a time.

```sql
BEGIN TRANSACTION;
  SELECT * FROM accounts WHERE name = 'Priya' FOR UPDATE; -- locks row
  UPDATE accounts SET balance = balance + 5000 WHERE name = 'Priya';
COMMIT;
```

**Use when:** Conflicts are frequent (payroll, payments, high-contention rows)

### Optimistic Locking
Don't lock. Before writing, check if anyone else changed the row. Retry if yes.

**Use when:** Conflicts are rare (user profile updates, low-contention rows)

### Deadlocks
Two transactions waiting for each other's locks forever.

```
Transaction A locks employees → waits for payments
Transaction B locks payments → waits for employees
→ Deadlock
```

**Fix 1:** Always acquire locks in the same order across all transactions
```javascript
// Both transactions: always lock employees first, then payments
await db.query('SELECT * FROM employees WHERE id = 1 FOR UPDATE');
await db.query('SELECT * FROM payments WHERE employee_id = 2 FOR UPDATE');
```

**Fix 2:** Set a lock timeout — database picks a victim and rolls it back
```sql
SET lock_timeout = '5s';
```

---

## 7. Performance Checklist

For any slow query:
1. Check for missing indexes on WHERE/JOIN columns
2. Check for `SELECT *` — replace with specific columns
3. Check GROUP BY includes all non-aggregated SELECT columns
4. Check date filters are in WHERE, not HAVING
5. Consider caching results with Redis if data doesn't change frequently
6. Run EXPLAIN to check for Seq Scans

---

## 8. Deel Interview Questions — Model Answers

**Q: Design a payments schema for a payroll system**
→ companies → employees → payments tables with proper foreign keys, DECIMAL for amounts, CHECK constraint for positive amounts, index on created_at and employee_id

**Q: Which isolation level for payroll processing and why?**
→ Read Committed (PostgreSQL default). Prevents dirty reads which are the real risk. Non-repeatable reads and phantom reads are unlikely due to payroll cutoff dates.

**Q: Two transactions updating the same employee's salary simultaneously?**
→ Use pessimistic locking with SELECT FOR UPDATE. Acquire locks in consistent order to prevent deadlocks. Set lock_timeout as safety net.

**Q: This query is slow — what do you do?**
→ Run EXPLAIN, look for Seq Scans, add composite index on WHERE columns, remove SELECT *, consider caching if query runs frequently.

**Q: What is a deadlock and how do you prevent it?**
→ Two transactions waiting for each other's locks. Prevent by always acquiring locks in the same order. Resolve with lock_timeout.
