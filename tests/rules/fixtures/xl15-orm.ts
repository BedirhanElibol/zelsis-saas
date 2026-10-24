import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const PG_PACKAGE = '{ "dependencies": { "pg": "^8.13.0", "typeorm": "^0.3.20" } }\n';
const MYSQL_PACKAGE = '{ "dependencies": { "mysql2": "^3.11.0", "typeorm": "^0.3.20" } }\n';

const commentEntity = (indexLine: string) => `import { Column, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { Post } from './post.entity';

@Entity('comments')
export class Comment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

${indexLine}  @ManyToOne(() => Post, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'post_id' })
  post: Post;

  @Column()
  body: string;
}
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [30315], name: 'XL-15 TypeORM cascade relation on Postgres without an index vs @Index and a MySQL app',
    detects: [...f('package.json', PG_PACKAGE), ...f('src/comments/comment.entity.ts', commentEntity(''))],
    ignores: [
      ...f('package.json', PG_PACKAGE),
      ...f('src/comments/comment.entity.ts', commentEntity('  @Index()\n')),
      ...f('src/likes/like.entity.ts', `import { Entity, Index, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { Post } from '../posts/post.entity';

@Entity('likes')
@Index(['post'])
export class Like {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => Post, { onDelete: 'CASCADE' })
  post: Post;
}
`),
    ],
  },
  {
    ruleIds: [30315], name: 'XL-15 TypeORM cascade relation is fine on MySQL (InnoDB indexes foreign keys)',
    detects: [...f('package.json', PG_PACKAGE), ...f('src/comments/comment.entity.ts', commentEntity(''))],
    ignores: [...f('package.json', MYSQL_PACKAGE), ...f('src/comments/comment.entity.ts', commentEntity(''))],
  },
  {
    ruleIds: [30315], name: 'XL-15 JPA @OnDelete(CASCADE) on Postgres without an index vs @Table(indexes)',
    detects: [
      ...f('src/main/resources/application.properties', 'spring.datasource.url=jdbc:postgresql://db:5432/app\n'),
      ...f('src/main/java/com/acme/OrderLine.java', `package com.acme;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Entity
@Table(name = "order_lines")
public class OrderLine {
  @Id
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @OnDelete(action = OnDeleteAction.CASCADE)
  @JoinColumn(name = "order_id")
  private Order order;
}
`),
    ],
    ignores: [
      ...f('src/main/resources/application.properties', 'spring.datasource.url=jdbc:postgresql://db:5432/app\n'),
      ...f('src/main/java/com/acme/OrderLine.java', `package com.acme;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Entity
@Table(name = "order_lines", indexes = @Index(columnList = "order_id"))
public class OrderLine {
  @Id
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @OnDelete(action = OnDeleteAction.CASCADE)
  @JoinColumn(name = "order_id")
  private Order order;
}
`),
    ],
  },
];
