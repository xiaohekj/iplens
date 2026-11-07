import { handler } from "../../../lib/handler.ts";

export const onRequest = (context: { request: Request }) => handler(context.request);