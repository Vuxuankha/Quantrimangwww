from contextlib import contextmanager
import sqlite3

import pytest
from fastapi import HTTPException

from webapi import scheduler40, jobs37, ops40, main, workbench45, cybersecurity51, security37


def _memory_connection():
    c=sqlite3.connect(':memory:')
    c.row_factory=sqlite3.Row
    return c


def _connection_factory(c):
    @contextmanager
    def connection():
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
    return connection


def test_schedule_missing_maps_to_404(monkeypatch):
    c=_memory_connection()
    c.execute('CREATE TABLE web_schedules40(id INTEGER PRIMARY KEY,operation TEXT,device_ids_json TEXT,network TEXT,parameters_json TEXT,interval_minutes INTEGER)')
    monkeypatch.setattr(scheduler40,'connection',_connection_factory(c))
    with pytest.raises(HTTPException) as exc:
        scheduler40.submit_schedule(999,{'id':1,'username':'Admin','role':'Admin'},manual=True)
    assert exc.value.status_code == 404
    assert exc.value.detail == 'Schedule not found'


def test_operator_cannot_run_admin_only_schedule_returns_403(monkeypatch):
    c=_memory_connection()
    c.execute('CREATE TABLE web_schedules40(id INTEGER PRIMARY KEY,operation TEXT,device_ids_json TEXT,network TEXT,parameters_json TEXT,interval_minutes INTEGER)')
    c.execute("INSERT INTO web_schedules40 VALUES(1,'DB_BACKUP','[]','','{}',60)")
    monkeypatch.setattr(scheduler40,'connection',_connection_factory(c))
    with pytest.raises(HTTPException) as exc:
        scheduler40.submit_schedule(1,{'id':2,'username':'op','role':'Operator'},manual=True)
    assert exc.value.status_code == 403
    assert exc.value.detail == 'TASK_PERMISSION_DENIED'


def test_schedule_status_tracks_actual_job_status(monkeypatch):
    c=_memory_connection()
    c.execute('CREATE TABLE web_schedules40(id INTEGER PRIMARY KEY,last_job_id INTEGER,last_status TEXT,updated_at TEXT)')
    c.execute("INSERT INTO web_schedules40(id,last_job_id,last_status) VALUES(1,7,'Queued')")
    monkeypatch.setattr(jobs37,'connection',_connection_factory(c))
    jobs37._sync_schedule_status(7,'Completed')
    row=c.execute('SELECT last_status FROM web_schedules40 WHERE id=1').fetchone()
    assert row['last_status'] == 'Completed'




def test_submit_schedule_closes_fast_job_completion_race(monkeypatch):
    c=_memory_connection()
    c.executescript("""
    CREATE TABLE web_schedules40(
      id INTEGER PRIMARY KEY,operation TEXT,device_ids_json TEXT,network TEXT,parameters_json TEXT,
      interval_minutes INTEGER,last_run TEXT,last_status TEXT,last_job_id INTEGER,next_epoch REAL,updated_at TEXT
    );
    CREATE TABLE web_jobs37(id INTEGER PRIMARY KEY,status TEXT);
    INSERT INTO web_schedules40(id,operation,device_ids_json,network,parameters_json,interval_minutes)
      VALUES(1,'DB_BACKUP','[]','','{}',60);
    """)
    monkeypatch.setattr(scheduler40,'connection',_connection_factory(c))
    def completed_before_return(operation,payload,user):
        c.execute("INSERT INTO web_jobs37(id,status) VALUES(77,'Completed')")
        c.commit()
        return {'id':77,'status':'Queued'}
    monkeypatch.setattr(jobs37.engine,'submit',completed_before_return)
    out=scheduler40.submit_schedule(1,{'id':1,'username':'Admin','role':'Admin'},manual=True)
    assert out['id']==77
    row=c.execute('SELECT last_job_id,last_status FROM web_schedules40 WHERE id=1').fetchone()
    assert row['last_job_id']==77
    assert row['last_status']=='Completed'

def test_scheduler_list_exposes_role_aware_can_run(monkeypatch):
    c=_memory_connection()
    c.execute('CREATE TABLE web_schedules40(id INTEGER PRIMARY KEY,operation TEXT)')
    c.executemany('INSERT INTO web_schedules40(id,operation) VALUES(?,?)',[(1,'DB_BACKUP'),(2,'PING')])
    monkeypatch.setattr(ops40,'connection',_connection_factory(c))
    monkeypatch.setattr(ops40,'require_role',lambda request,*roles:{'id':2,'username':'op','role':'Operator'})
    rows=ops40.schedules(None)
    by_op={r['operation']:r for r in rows}
    assert by_op['DB_BACKUP']['can_run'] is False
    assert by_op['PING']['can_run'] is True


def test_scan_import_initializes_table_before_lookup(monkeypatch):
    c=_memory_connection()
    monkeypatch.setattr(main,'get_connection',lambda:c)
    with pytest.raises(HTTPException) as exc:
        main.import_scan_result(999)
    assert exc.value.status_code == 404
    assert c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_scan_results'").fetchone()


def test_security_close_initializes_table_before_lookup(monkeypatch):
    c=_memory_connection()
    monkeypatch.setattr(workbench45,'connection',_connection_factory(c))
    monkeypatch.setattr(workbench45,'require_role',lambda request,*roles:{'id':1,'username':'Admin','role':'Admin'})
    import modules.enterprise_security as es
    monkeypatch.setattr(es,'ensure_enterprise_security_tables',lambda:c.execute('CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY,status TEXT)'))
    monkeypatch.setattr(es,'close_event',lambda event_id:None)
    with pytest.raises(HTTPException) as exc:
        workbench45.security_close(999,None)
    assert exc.value.status_code == 404


def test_mfa_reset_missing_user_returns_404(monkeypatch):
    monkeypatch.setattr(cybersecurity51,'require_role',lambda request,*roles:{'username':'Admin','role':'Admin'})
    monkeypatch.setattr(security37,'reset_mfa',lambda user_id:False)
    with pytest.raises(HTTPException) as exc:
        cybersecurity51.admin_reset_mfa(999,None)
    assert exc.value.status_code == 404


def test_only_one_request_validation_handler_is_registered_in_source():
    src=open('webapi/main.py',encoding='utf-8').read()
    assert src.count('@app.exception_handler(RequestValidationError)') == 1


def test_scheduler_ui_hides_run_button_when_can_run_false():
    src=open('webapi/static/app.js',encoding='utf-8').read()
    assert "r.can_run?button('Run now'" in src
    assert 'Không có quyền chạy' in src
