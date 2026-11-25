// Long-running server (local, Docker, VPS, Render, Koyeb...). Syncs mail in the background.
import { app, ready } from './lib/app.js';
import { startSyncLoop } from './lib/imapSync.js';

const port = Number(process.env.PORT || 3000);

await ready();
app.listen(port, () => {
  console.log(`G2G Auth running on http://localhost:${port}`);
  startSyncLoop(Number(process.env.SYNC_INTERVAL || 60));
});
