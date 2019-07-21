-- spam table
create table IF not exists spam
(
    user    TEXT,
    domain  TEXT,
    ts      TEXT,
    message TEXT,
    primary key (domain, ts)
);

-- indicies
create index if not exists domain_tx_idx
    on spam (domain, ts);

create index if not exists user_domain_idx
    on spam (user, domain);
