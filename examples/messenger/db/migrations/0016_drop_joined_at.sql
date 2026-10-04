-- 0016: the policy no longer reads ms.joined_at() (0015): reading since joining goes by ms.joined_seq().
DROP FUNCTION ms.joined_at(bigint);
