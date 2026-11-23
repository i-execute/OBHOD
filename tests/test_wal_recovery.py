import importlib.util
import json
import os
from pathlib import Path
import pytest


def load():
    spec=importlib.util.spec_from_file_location('walagent',str(Path(__file__).resolve().parents[1] / 'Storage/remote/ddos_agent.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def prepared(tmp_path):
    m=load();flags={'dir':str(tmp_path)};policy=m.policy_from({},{});body=m.rules_text(policy,flags)
    m.wal_write(flags,policy,body)
    return m,flags,policy,body


def test_roundtrip_and_mode(tmp_path):
    m,flags,policy,body=prepared(tmp_path)
    assert m.wal_read(flags)[:2]==(policy,body)
    assert os.stat(m.wal_path(flags)).st_mode & 0o777 == 0o600
    with pytest.raises(m.DDosError) as exc: m.wal_write(flags,policy,body)
    assert exc.value.code=='pending_policy'


@pytest.mark.parametrize('corrupt', ['truncated', 'hash', 'version', 'config', 'policy', 'rules', 'symlink'])
def test_corrupt_or_misdirected_wal_never_changes_files(tmp_path,monkeypatch,corrupt):
    m,flags,policy,body=prepared(tmp_path)
    wal=Path(m.wal_path(flags)); obj=json.loads(wal.read_text())
    if corrupt=='truncated': wal.write_text('{')
    elif corrupt=='symlink':
        target=tmp_path/'replacement';target.write_text(wal.read_text());wal.unlink();wal.symlink_to(target)
    else:
        if corrupt=='hash': obj['sha256']='bad'
        if corrupt=='version': obj['payload']['version']=2
        if corrupt=='config': obj['payload']['config']=str(tmp_path/'other')
        if corrupt=='policy': obj['payload']['policy']['enabled']=False
        if corrupt=='rules': obj['payload']['rules']='nft invalid'
        if corrupt!='hash':
            import hashlib
            raw=json.dumps(obj['payload'],ensure_ascii=False,sort_keys=True,separators=(',',':'))
            obj['sha256']=hashlib.sha256(raw.encode()).hexdigest()
        wal.write_text(json.dumps(obj))
    monkeypatch.setattr(m,'apply_rules',lambda *args,**kwargs:pytest.fail('invalid WAL changed firewall'))
    with pytest.raises(m.DDosError) as exc:m.recover_policy(flags,automatic=True)
    assert exc.value.code=='bad_transaction'
    assert not Path(m.conf_path(flags)).exists()


def test_ordinary_failed_apply_rolls_back_and_removes_wal(tmp_path,monkeypatch):
    m=load(); flags={'dir':str(tmp_path)};conf=Path(m.conf_path(flags));rules=Path(m.rules_path(flags))
    conf.write_text('{"enabled":true}\n');rules.write_text('old')
    monkeypatch.setattr(m,'apply_rules',lambda *args,**kwargs: (_ for _ in ()).throw(m.DDosError('apply','failed','apply')))
    with pytest.raises(m.DDosError) as exc:m.commit_policy_change(flags,m.policy_from({},{}),force=True)
    assert exc.value.code=='apply' and conf.read_text()=='{"enabled":true}\n' and rules.read_text()=='old'
    assert not Path(m.wal_path(flags)).exists()


def test_failed_nft_rollback_keeps_wal_and_blocks_next_mutation(tmp_path,monkeypatch):
    m=load();flags={'dir':str(tmp_path)};conf=Path(m.conf_path(flags));rules=Path(m.rules_path(flags))
    conf.write_text('{"enabled":true}\n');rules.write_text('old')
    monkeypatch.setattr(m,'apply_rules',lambda *args,**kwargs: (_ for _ in ()).throw(m.DDosError('rollback_failed','failed','apply')))
    with pytest.raises(m.DDosError) as exc:m.commit_policy_change(flags,m.policy_from({},{}),force=True)
    assert exc.value.code=='rollback_failed' and Path(m.wal_path(flags)).is_file()
    with pytest.raises(m.DDosError) as exc:m.commit_policy_change(flags,m.policy_from({},{}),force=True)
    assert exc.value.code=='pending_policy'


def test_recovery_replays_frozen_rules_without_regenerating(tmp_path,monkeypatch):
    m,flags,policy,body=prepared(tmp_path)
    called=[]
    monkeypatch.setattr(m,'apply_rules',lambda flags,policy,prepared=None: called.append(prepared))
    monkeypatch.setattr(m,'rules_text',lambda *args,**kwargs:pytest.fail('unexpected regeneration'))
    assert m.recover_policy(flags,automatic=True)['policy_recovered']
    assert called==[body] and not Path(m.wal_path(flags)).exists()


def test_uncertain_rollback_changes_wal_to_manual_and_boot_refuses(tmp_path,monkeypatch):
    m=load();flags={'dir':str(tmp_path)};p=m.policy_from({},{});path=Path(m.conf_path(flags));path.write_text('{"enabled":true}')
    Path(m.rules_path(flags)).write_text('old')
    monkeypatch.setattr(m,'apply_rules',lambda *args,**kwargs: (_ for _ in ()).throw(m.DDosError('rollback_failed','ambiguous','apply')))
    with pytest.raises(m.DDosError):m.commit_policy_change(flags,p,force=True)
    assert m.wal_state(flags)['state']=='manual'
    with pytest.raises(m.DDosError) as exc:m.recover_policy(flags,automatic=True)
    assert exc.value.code=='pending_manual'


def test_confirmation_digest_must_be_current(tmp_path,monkeypatch):
    m,flags,policy,body=prepared(tmp_path)
    monkeypatch.setattr(m,'apply_rules',lambda *args,**kwargs:None)
    with pytest.raises(m.DDosError) as exc:m.recover_policy({**flags,'expected_sha':'0'*64})
    assert exc.value.code=='stale_recovery' and not Path(m.conf_path(flags)).exists()
    digest=m.wal_state(flags)['sha256']
    assert m.recover_policy({**flags,'expected_sha':digest})['policy_recovered']


def test_journal_fsync_error_after_rename_switches_to_manual(tmp_path,monkeypatch):
    m=load();flags={'dir':str(tmp_path)};policy=m.policy_from({},{});path=Path(m.wal_path(flags));original=m.write_atomic;hit=False
    def fail_once(path,text,mode=0o644):
        nonlocal hit
        result=original(path,text,mode)
        if str(path)==str(m.wal_path(flags)) and not hit:
            hit=True;raise m.DDosError('fs','injected','fs')
        return result
    monkeypatch.setattr(m,'write_atomic',fail_once)
    with pytest.raises(m.DDosError):m.commit_policy_change(flags,policy,force=True)
    assert hit and path.exists() and m.wal_state(flags)['state']=='manual'
    assert not Path(m.conf_path(flags)).exists()


def test_world_readable_or_fifo_journal_fails_closed(tmp_path):
    m,flags,policy,body=prepared(tmp_path)
    wal=Path(m.wal_path(flags));wal.chmod(0o644)
    with pytest.raises(m.DDosError) as exc:m.wal_read(flags)
    assert exc.value.code=='bad_transaction'
    wal.unlink();os.mkfifo(wal,0o600)
    with pytest.raises(m.DDosError) as exc:m.wal_read(flags)
    assert exc.value.code=='bad_transaction'
