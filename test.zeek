global responseCounter:table[addr] of count;
global _404Counter:count;
global uniqueURLCounter:count;

event zeek_init()
{
  local t:SumStats::Reducer  = [$stream = "scan_detect_404.lookup", $apply = set(SumStats::UNIQUE)];
  SumStats::create([$name     = "scan_detect_url",
                    $epoch    = 10min,
                    $reducers = set(t),
                    $epoch_result(ts:time, key:SumStats::Key, result:SumStats::Result) = 
                    {
                      _404Counter      = result["scan_detect_404.lookup"]$num;
                      uniqueURLCounter = result["scan_detect_404.lookup"]$unique;
                      if ( (_404Counter > 2) && (_404Counter > 0.2 * responseCounter[key$host]) && (uniqueURLCounter > 0.5 * _404Counter) )
                        print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, _404Counter, uniqueURLCounter);
                    }
                   ]);
}

event http_reply(c:connection, version:string, code:count, reason:string)
{
  if (c$id$orig_h in responsesCounter)
    ++responseCounter[c$id$orig_h];
  else
    responseCounter[c$id$orig_h] = 1;
  if (code == 404)
    SumStats::observe("scan_detect_404.lookup", [$host = c$id$orig_h], [$str = c$http$uri]);
}
