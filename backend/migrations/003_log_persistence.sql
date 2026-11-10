-- Durable log compatibility: page views include dynamically served project pages too.
-- The API already validates route segments; the old fixed-page CHECK prevented
-- those valid views from being persisted.
alter table view_logs drop constraint if exists view_logs_page_check;
