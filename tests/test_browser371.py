"""Execute the actual dashboard script with an isolated JS engine and minimal DOM."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, '/tmp/vpn371-js')
try:
    import quickjs
except ImportError:
    quickjs = None
from test_manager import m
import vpn_admin as admin


@unittest.skipUnless(quickjs, 'optional isolated QuickJS engine required')
class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.ctx = quickjs.Context()
        self.ctx.eval(r'''
let now=0, fetches=0, listeners={}, intervals={}, forms=[{disabled:false}];
let management={dataset:{countdown:'1800'},textContent:''};
let delivery={dataset:{countdown:'3600',delivery:'abc'},textContent:''};
let memory={textContent:''}, services={textContent:''}, updated={textContent:''};
let payload={remaining:1790,health:{memory:{MemAvailable:128,MemTotal:512},services:{ipsec:'active'},sampled_at:10000},jobs:[],batches:[],links:[{hash:'abc',remaining:7200}]};
const performance={now:()=>now};
const document={readyState:'loading',hidden:false,
 querySelector:selector=>selector==='[data-management]'?management:selector==='[data-memory]'?memory:selector==='[data-services]'?services:selector==='[data-updated]'?updated:null,
 querySelectorAll:selector=>selector.startsWith('[data-countdown]')?[delivery]:selector.startsWith('form ')?forms:[],
 addEventListener:(name,fn)=>listeners[name]=fn};
function setInterval(fn,delay){intervals[delay]=fn;}
function setTimeout(fn,delay){return 1;}
function clearTimeout(id){}
class AbortController{constructor(){this.signal={};}abort(){}}
function fetch(){fetches++;return Promise.resolve({status:200,ok:true,json:()=>Promise.resolve(payload)});}
''')
        self.ctx.eval(admin.SCRIPT)

    def settle(self):
        for _ in range(100):
            if not self.ctx.execute_pending_job():
                return
        self.fail('Unbounded promise activity')

    def test_script_waits_for_late_delivery_markup_and_ticks_without_requests(self):
        self.assertEqual(self.ctx.eval('fetches'), 0)
        self.ctx.eval("listeners.DOMContentLoaded()")
        self.settle()
        self.assertEqual(self.ctx.eval('delivery.textContent'), '02:00:00')
        self.assertEqual(self.ctx.eval('management.textContent'), '00:29:50')
        self.ctx.eval('now=5000;intervals[1000]()')
        self.assertEqual(self.ctx.eval('management.textContent'), '00:29:45')
        self.assertEqual(self.ctx.eval('fetches'), 1)
        self.ctx.eval('document.hidden=true;intervals[15000]()')
        self.settle()
        self.assertEqual(self.ctx.eval('fetches'), 1)
        self.ctx.eval("document.hidden=false;listeners.visibilitychange()")
        self.settle()
        self.assertEqual(self.ctx.eval('fetches'), 2)

    def test_expiry_disables_actions_and_stops_polling(self):
        self.ctx.eval('listeners.DOMContentLoaded()')
        self.settle()
        self.ctx.eval('now=1800000;intervals[1000]()')
        self.assertTrue(self.ctx.eval('forms[0].disabled'))
        before=self.ctx.eval('fetches')
        self.ctx.eval('intervals[15000]()')
        self.settle()
        self.assertEqual(self.ctx.eval('fetches'), before)
        self.assertEqual(self.ctx.eval('management.textContent'), 'Management expired')

    def test_network_failure_does_not_freeze_local_expiry(self):
        self.ctx.eval("fetch=()=>{fetches++;return Promise.reject(Error('down'));};listeners.DOMContentLoaded()")
        self.settle()
        self.assertIn('unavailable', self.ctx.eval('updated.textContent'))
        self.ctx.eval('now=10000;intervals[1000]()')
        self.assertEqual(self.ctx.eval('management.textContent'), '00:29:50')
