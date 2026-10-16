import tempfile

from jarvis_crawl.device import FakeClock
from jarvis_crawl.fakeapp import FakeDevice
from jarvis_crawl.runner import RunConfig, Runner
from jarvis_crawl.schema import read_episode
from jarvis_crawl.statehash import UINode


def run_fake(tmp, seed=7, steps=50, device_seed=None, **kw):
    clock = FakeClock()
    dev = FakeDevice(clock, seed=seed if device_seed is None else device_seed)
    runner_kw = {k: kw.pop(k) for k in ("policy_obj", "kill", "reward_fn", "safety") if k in kw}
    cfg = RunConfig(app_pkg="com.fake.shop", out_dir=tmp, max_steps=steps, seed=seed, **kw)
    r = Runner(cfg, dev, clock, policy=runner_kw.get("policy_obj"), kill=runner_kw.get("kill"),
               reward_fn=runner_kw.get("reward_fn"), safety=runner_kw.get("safety"))
    res = r.run()
    return dev, read_episode(res["episode_path"]), res


def node(text="", rid="", desc="", cls="android.widget.Button", pkg="com.fake.shop", clickable=True,
         editable=False, password=False, checkable=False):
    return UINode(idx=1, path="0/0", depth=1, parent=0, cls=cls, rid=rid, text=text, desc=desc, pkg=pkg,
                  clickable=clickable, long_clickable=False, scrollable=False, checkable=checkable, enabled=True,
                  password=password, editable=editable, bounds=(0, 0, 100, 100))
