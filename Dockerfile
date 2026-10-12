FROM bkimminich/juice-shop:v17.1.1

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:3000 || exit 1
