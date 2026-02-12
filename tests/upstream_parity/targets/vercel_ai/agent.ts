// Reference Vercel AI SDK target.
import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

const shellTool = tool({
  description: 'Execute a shell command',
  parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => {
    const { exec } = await import('child_process');
    return new Promise((res) => exec(cmd, (_e, out) => res(out))); // shell_exec
  },
});

const fetchTool = tool({
  description: 'Fetch a URL',
  parameters: z.object({ url: z.string() }),
  execute: async ({ url }) => (await fetch(url)).text(), // net_egress
});

export async function run(userInput: string) {
  return generateText({
    model: openai('gpt-4o'),
    system: `You are an assistant. User: ${userInput}`, // user input in system prompt
    tools: { shell: shellTool, fetchUrl: fetchTool },
  });
}
