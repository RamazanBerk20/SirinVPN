import { Fragment, type ReactNode } from "react";
import { t, type MessageKey, type MessageParams } from ".";

/**
 * Renders a message that contains simple tags, such as "Open <settings>Android settings</settings>".
 * Translators move the tags with the words; each tag name maps to a renderer here.
 */
export function Rich({ id, params, tags }: {
  id: MessageKey;
  params?: MessageParams;
  tags: Record<string, (content: ReactNode) => ReactNode>;
}) {
  const parts = t(id, params).split(/<(\w+)>(.*?)<\/\1>/gs);
  const nodes: ReactNode[] = [];
  for (let index = 0; index < parts.length; index += 3) {
    if (parts[index]) nodes.push(parts[index]);
    const name = parts[index + 1];
    if (name !== undefined) nodes.push(tags[name] ? tags[name](parts[index + 2]) : parts[index + 2]);
  }
  return <>{nodes.map((node, index) => <Fragment key={index}>{node}</Fragment>)}</>;
}
