"""create_phase2a_recon_tables

Revision ID: 942c1dc69308
Revises: 
Create Date: 2026-11-24 20:33:20.440273

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '942c1dc69308'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organizations
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(100), unique=True, nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Users
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(255), unique=True, index=True, nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(100), nullable=True),
        sa.Column('role', sa.String(50), default='Analyst', nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Projects
    op.create_table(
        'projects',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Targets
    op.create_table(
        'targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('base_url', sa.String(2048), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('asset_criticality', sa.Float(), default=1.0, nullable=False),
        sa.Column('verified', sa.Boolean(), default=False, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Scope Rules
    op.create_table(
        'scope_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('targets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rule_type', sa.String(20), default='INCLUDE', nullable=False),
        sa.Column('pattern', sa.String(1024), nullable=False),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Scan Jobs
    op.create_table(
        'scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('targets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile', sa.String(50), default='QUICK_ASSESSMENT', nullable=False),
        sa.Column('status', sa.String(50), default='QUEUED', nullable=False, index=True),
        sa.Column('max_crawl_depth', sa.Integer(), default=3, nullable=False),
        sa.Column('max_urls', sa.Integer(), default=500, nullable=False),
        sa.Column('concurrency', sa.Integer(), default=5, nullable=False),
        sa.Column('rate_limit_rps', sa.Float(), default=10.0, nullable=False),
        sa.Column('urls_crawled', sa.Integer(), default=0, nullable=False),
        sa.Column('findings_count', sa.Integer(), default=0, nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Discovered Endpoints
    op.create_table(
        'discovered_endpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('normalized_url', sa.String(2048), nullable=False, index=True),
        sa.Column('method', sa.String(10), default='GET', nullable=False),
        sa.Column('parameter', sa.String(255), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(100), nullable=True),
        sa.Column('response_size', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Float(), nullable=True),
        sa.Column('source_url', sa.String(2048), nullable=True),
        sa.Column('discovery_method', sa.String(50), default='CRAWLER', nullable=False),
        sa.Column('crawl_depth', sa.Integer(), default=0, nullable=False),
        sa.Column('endpoint_category', sa.String(50), default='PAGE', nullable=False),
        sa.Column('query_params', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Discovered Forms
    op.create_table(
        'discovered_forms',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('endpoint_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('discovered_endpoints.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_url', sa.String(2048), nullable=False),
        sa.Column('method', sa.String(10), default='POST', nullable=False),
        sa.Column('fields', sa.JSON(), nullable=False),
        sa.Column('enctype', sa.String(100), nullable=True),
        sa.Column('source_url', sa.String(2048), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )

    # Technology Observations
    op.create_table(
        'technology_observations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('technology_name', sa.String(100), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Float(), default=0.8, nullable=False),
        sa.Column('detection_source', sa.String(50), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)
    )


def downgrade() -> None:
    op.drop_table('technology_observations')
    op.drop_table('discovered_forms')
    op.drop_table('discovered_endpoints')
    op.drop_table('scan_jobs')
    op.drop_table('scope_rules')
    op.drop_table('targets')
    op.drop_table('projects')
    op.drop_table('users')
    op.drop_table('organizations')
