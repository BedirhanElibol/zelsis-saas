import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'How to Find and Fix N+1 Queries (Prisma, Django, Rails, Laravel) - Zelsis Guides',
  description:
    'A page that runs one query per row is fast with ten rows and times out with ten thousand. How to spot N+1 queries, fix them in Prisma, Django, Rails and Laravel, and count queries in a test.',
  alternates: { canonical: '/guides/n-plus-one-queries' },
};

const H2 = 'text-xl font-semibold text-white';

export default function NPlusOnePage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">How to find and fix N+1 queries</h1>
      <p className="text-zinc-400">
        An N+1 query is one query to load a list, then one more query for each item in it. With ten products in your test database the
        page feels instant. With ten thousand in production it sends ten thousand and one queries, and the page times out on the day
        you get traffic. Reviews miss it because the loop and the query usually sit in different places: the loop in a component, the
        query inside a helper.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>What it looks like</h2>
        <CodeBlock
          tone="bad"
          label="Prisma: one query for orders, then one per order"
          code={`const orders = await prisma.order.findMany({ where: { shopId } });
for (const order of orders) {
  order.customer = await prisma.customer.findUnique({ where: { id: order.customerId } });
}`}
        />
        <CodeBlock
          tone="good"
          label="Prisma: two queries in total, whatever the number of orders"
          code={`const orders = await prisma.order.findMany({
  where: { shopId },
  include: { customer: true },
});`}
        />
        <p className="text-zinc-300">
          When there is no relation to include, collect the IDs and load them in one query with <code>where: {'{'} id: {'{'} in: ids {'}'}{' }'}</code>,
          then match them up in memory.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>The same fix in other frameworks</h2>
        <CodeBlock
          tone="good"
          label="Django"
          code={`# ForeignKey / OneToOne: a join
orders = Order.objects.filter(shop=shop).select_related("customer")
# ManyToMany / reverse ForeignKey: one extra query for all rows
orders = Order.objects.filter(shop=shop).prefetch_related("items")`}
        />
        <CodeBlock
          tone="good"
          label="Rails"
          code={`orders = Order.where(shop: shop).includes(:customer, :items)`}
        />
        <CodeBlock
          tone="good"
          label="Laravel"
          code={`$orders = Order::where('shop_id', $shopId)->with(['customer', 'items'])->get();`}
        />
        <CodeBlock
          tone="good"
          label="Plain SQL"
          code={`select o.*, c.name as customer_name
from orders o
join customers c on c.id = o.customer_id
where o.shop_id = $1;`}
        />
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Catch it with a test</h2>
        <TestStep>
          Turn on query logging in development (<code>log: [&apos;query&apos;]</code> in Prisma, <code>django.db.backends</code> at DEBUG,
          the Rails log, or <code>DB::listen</code> in Laravel) and load the page. If the same query repeats with only the ID changing,
          you have an N+1.
        </TestStep>
        <TestStep>
          Seed 50 rows and assert the number of queries in a test. Django has <code>assertNumQueries</code>; in Rails the{' '}
          <code>bullet</code> gem raises on N+1 in tests. The count must stay the same with 5 rows and with 50.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'DB-PERF-01', title: 'ORM query inside a loop (N+1)' }]}>
        Zelsis flags database calls made inside a loop over query results in each pull request, so the slow page is caught before it
        merges instead of on the day you get traffic.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
