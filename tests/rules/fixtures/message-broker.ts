import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile => ({ path, content });

export const CASES: RuleCase[] = [
  {
    ruleIds: [12506], name: 'MQ-06 amqplib consumer nacks with the default requeue in catch vs requeue=false after one retry',
    detects: [f('workers/orders.js', `const amqp = require('amqplib');

async function start() {
  const conn = await amqp.connect(process.env.AMQP_URL);
  const channel = await conn.createChannel();
  await channel.consume('orders', async (msg) => {
    try {
      await handleOrder(JSON.parse(msg.content.toString()));
      channel.ack(msg);
    } catch (err) {
      console.error(err);
      channel.nack(msg);
    }
  });
}
`)],
    ignores: [f('workers/orders.js', `const amqp = require('amqplib');

async function start() {
  const conn = await amqp.connect(process.env.AMQP_URL);
  const channel = await conn.createChannel();
  await channel.consume('orders', async (msg) => {
    try {
      await handleOrder(JSON.parse(msg.content.toString()));
      channel.ack(msg);
    } catch (err) {
      channel.nack(msg, false, false);
      return Promise.reject(err);
    }
  });
}
`)],
  },
  {
    ruleIds: [12506], name: 'MQ-06 pika consumer basic_nack without requeue=False in except vs one that checks redelivered',
    detects: [f('worker/consumer.py', `import json
import pika


def on_message(ch, method, properties, body):
    try:
        process(json.loads(body))
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception:
        ch.basic_nack(delivery_tag=method.delivery_tag)


channel.basic_consume(queue="jobs", on_message_callback=on_message)
`)],
    ignores: [f('worker/consumer.py', `import json
import pika


def on_message(ch, method, properties, body):
    try:
        process(json.loads(body))
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception:
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=not method.redelivered)


channel.basic_consume(queue="jobs", on_message_callback=on_message)
`)],
  },
];
