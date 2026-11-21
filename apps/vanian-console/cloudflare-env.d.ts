declare namespace Cloudflare {
  interface Env {
    DB?: D1Database;
    BUCKET?: R2Bucket;
    VANIAN_API_ORIGIN?: string;
    VANIAN_API_TOKEN?: string;
    VANIAN_LIVE_MEMBERS?: string;
  }
}
