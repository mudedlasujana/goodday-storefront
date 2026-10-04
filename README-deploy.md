# Nuvora

Nuvora is a full-stack demo store. It can run as a local static prototype (`index.html`) or as an online Render app with shared customer accounts, carts, inventory, and orders backed by PostgreSQL.

## Deploy to Render

1. Push this folder to a GitHub repository.
2. In Render, create a Blueprint from that repository and select `render.yaml`.
3. Review the resources before creating them. The blueprint currently uses Render Free services; the free PostgreSQL database expires after 30 days, so upgrade it before then if you want to keep account/order data.
4. When the deployment finishes, Render provides a public `onrender.com` URL that can be opened on any laptop.

Render deployment requires a connected GitHub repository and Render account. No real payment gateway is configured: online payment selections are recorded as demo payments, and cash on delivery is recorded as pending.
