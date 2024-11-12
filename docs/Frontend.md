### Frontend Architecture
  - Submission Server: API in Lua, insert/edit in database
  - Database Server: PoistgreSQL, manage insertion queue, keeps list info
  - Worker: processes the queue in the Database, does preliminary check + transparency log submission
  - Submission Transparency Log: Trillian
  - Artifact Transparency Log: Trillian
  - List Builder: C?
  - CDN Distirbution

![Frontend diagram](https://github.com/freedomofpress/webcat/blob/48d72ad79e2e9ac7a9e98628f6639fa35e75ba63/docs/images/frontend.drawio.png)
