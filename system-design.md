**System Design Mastery: 12-Week Study Plan**

This plan breaks down system-design topics into a week-by-week roadmap. Each week mixes reading, videos, and hands-on projects to build intuition. Key concepts and resources are listed for each week. Aim for **\~20 hours/week**: reading chapters or articles, watching lectures, and implementing mini-projects or design exercises.

---

### Recommended Books (Use Throughout the Plan)

1. **Designing Data-Intensive Applications** by Martin Kleppmann
   [https://dataintensive.net/](https://dataintensive.net/)
2. **Building Microservices** by Sam Newman
   [https://www.oreilly.com/library/view/building-microservices/9781491950340/](https://www.oreilly.com/library/view/building-microservices/9781491950340/)
3. **System Design Interview** by Alex Xu
   [https://www.amazon.com/System-Design-Interview-insiders-Second/dp/B08CMF2CQF](https://www.amazon.com/System-Design-Interview-insiders-Second/dp/B08CMF2CQF)
4. **The Art of Scalability** by Martin L. Abbott and Michael T. Fisher
   [https://www.pearson.com/en-us/subject-catalog/p/the-art-of-scalability/P200000004784](https://www.pearson.com/en-us/subject-catalog/p/the-art-of-scalability/P200000004784)
5. **Release It!** by Michael T. Nygard
   [https://www.oreilly.com/library/view/release-it-2nd/9781680502398/](https://www.oreilly.com/library/view/release-it-2nd/9781680502398/)
6. **Site Reliability Engineering** by Google (Betsy Beyer et al.)
   [https://sre.google/books/](https://sre.google/books/)

---

### Week 1: Fundamentals of Scalability & Load Balancing

**Concepts:** Scalability, Load Balancing, Stateless vs Stateful Services, CQRS Basics
**Resources:**

* [Scaling Simplified - Google Cloud](https://cloud.google.com/blog/products/identity-security/scaling-simplified-how-distributed-systems-handle-millions)
* *Designing Data-Intensive Applications* by Martin Kleppmann – Chapter 4, 7
* [System Design Primer - GitHub](https://github.com/donnemartin/system-design-primer)
* [Load Balancing Basics - DigitalOcean](https://www.digitalocean.com/community/tutorials/an-introduction-to-load-balancing)

### Week 2: Databases – SQL vs NoSQL, Replication & Sharding

**Concepts:** SQL/NoSQL, ACID/BASE, Replication, Sharding
**Resources:**

* *Designing Data-Intensive Applications* – Chapters 2–3
* [CAP Theorem - IBM](https://www.ibm.com/cloud/learn/cap-theorem)
* [NoSQL Databases Explained - MongoDB](https://www.mongodb.com/nosql-explained)
* [Sharding vs Replication - GeeksforGeeks](https://www.geeksforgeeks.org/difference-between-sharding-and-replication/)

### Week 3: Caching & Data Partitioning

**Concepts:** Caching Strategies, Eviction Policies, CDN, Consistent Hashing
**Resources:**

* [Caching Strategies - AWS](https://aws.amazon.com/caching/)
* [Consistent Hashing Explained - Medium](https://medium.com/@ankurhanda/consistent-hashing-a-beginners-guide-8a5c0c8e2f6d)
* [Redis Caching Tutorial](https://redis.io/docs/latest/)

### Week 4: Consistency Models, CAP Theorem, and Fault Tolerance

**Concepts:** CAP, Eventual/Strong Consistency, Fault Tolerance, Quorum, Redundancy
**Resources:**

* [ScyllaDB: Consistency Models](https://www.scylladb.com/glossary/consistency-model/)
* [CAP Theorem Deep Dive - Confluent](https://www.confluent.io/blog/event-driven-microservices-apache-kafka-cdc/)
* [Netflix Tech Blog](https://netflixtechblog.com/)

### Week 5: APIs and Microservices Architecture

**Concepts:** REST API Design, Versioning, Microservices, Service Discovery, Docker/K8s Intro
**Resources:**

* [API Design Guide - Google](https://cloud.google.com/apis/design)
* *Building Microservices* by Sam Newman
* [Microservices - Atlassian](https://www.atlassian.com/microservices)

### Week 6: Message Queues & Asynchronous Processing

**Concepts:** Queues, Pub/Sub, Eventual Consistency, Dead-letter Queues
**Resources:**

* [RabbitMQ Tutorial](https://www.rabbitmq.com/getstarted.html)
* [Kafka Introduction](https://kafka.apache.org/intro)
* [Message Queue Design Patterns - Educative](https://www.educative.io/blog/message-queue-architecture)

### Week 7: System Monitoring and Observability

**Concepts:** Logs, Metrics, Tracing, Prometheus, Grafana, ELK Stack
**Resources:**

* [Prometheus Intro](https://prometheus.io/docs/introduction/overview/)
* [Grafana Quickstart](https://grafana.com/docs/grafana/latest/getting-started/getting-started-prometheus/)
* [What is Observability - Splunk](https://www.splunk.com/en_us/data-insider/what-is-observability.html)

### Week 8: Rate Limiting and Throttling

**Concepts:** Token Bucket, Leaky Bucket, Sliding Window, HTTP 429, Quotas
**Resources:**

* [Rate Limiting Algorithms - Cloudflare](https://developers.cloudflare.com/rate-limiting/)
* [Solo.io Rate Limiting Overview](https://www.solo.io/blog/rate-limiting/)
* [NGINX Rate Limiting](https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-pro/)

### Week 9: High Availability and Fault Tolerance

**Concepts:** HA Architectures, Chaos Engineering, Redundancy, Disaster Recovery
**Resources:**

* [AWS High Availability Guide](https://aws.amazon.com/builders-library/reliability/)
* [Chaos Engineering - Principles of Chaos](https://principlesofchaos.org/)
* [Netflix Chaos Monkey](https://github.com/Netflix/chaosmonkey)

### Week 10: Advanced Topics – Consensus and Distributed Transactions

**Concepts:** Paxos, Raft, 2PC, Sagas, CRDTs, Event Sourcing
**Resources:**

* [Raft Consensus Algorithm - The Morning Paper](https://blog.acolyer.org/2015/03/04/raft-consensus-algorithm/)
* [Two-Phase Commit - IBM](https://www.ibm.com/docs/en/order-management-sw/10.0?topic=protocols-two-phase-commit)
* [Event Sourcing and CQRS - Martin Fowler](https://martinfowler.com/eaaDev/EventSourcing.html)

### Week 11: Real-World Architecture Case Studies

**Concepts:** Scalable Patterns in Practice, Service Evolution, Polyglot Persistence
**Resources:**

* [ByteByteGo - System Design Case Studies](https://bytebytego.com/)
* [Uber Engineering Blog](https://eng.uber.com/)
* [WhatsApp Scaling Architecture](https://blog.whatsapp.com/)

### Week 12: Capstone Project & Review

**Goal:** Synthesize Learning by Designing and Partially Building a Scalable System
**Project Ideas:** Social Network, Chat App, IoT Pipeline, E-commerce Platform
**Resources:**

* *System Design Interview* by Alex Xu
* *Release It!* by Michael T. Nygard
* [System Design Discord/Communities](https://discord.gg/systemdesign)

---

**Notes:**

* Use a mix of books, tutorials, courses, and blogs to reinforce learning.
* Regularly revisit and refine earlier concepts as they build on each other.
* Share your designs with peers and get feedback to improve.

By the end of this plan, you’ll be able to design scalable systems from scratch with a deep understanding of distributed design patterns, tradeoffs, and industry practices.
