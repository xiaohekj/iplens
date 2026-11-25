import { handler } from "../../../lib/handler.ts";

export const onRequest = (context: {
  request: Request;
  env?: Record<string, unknown>;
}) => handler(context.request, context.env);