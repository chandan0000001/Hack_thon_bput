"""Project management (ORG-REDESIGN): create / list / archive org projects.

A project is a scoped gateway + dashboard surface inside one organization.
Slug rules:

- Derived from the name via the same normalization the org slugifier uses.
- Unique per organization (DB UNIQUE (organization_id, slug) in migration
  0019); a duplicate NAME inside the same org is a ConflictError, not a
  silent salt — project names are identifiers on gateway URLs.
- A duplicate slug collision (e.g. "Demo" vs "demo!") falls back to the
  ``-2`` salt pattern.

Archive is a soft delete (``status='archived'``): history keeps its
project_id stamp, the gateway 404s on archived slugs, and the project
disappears from the switcher. API keys are not deleted; they simply stop
resolving because every gateway request re-checks project status.
"""

import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError
from app.db.models import Project

logger = logging.getLogger("cyberguard.projects")


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name).strip().lower()
    slug = re.sub(r"[-\s]+", "-", slug)
    return slug[:60]


async def create_project(
    db: AsyncSession, *, org_id: str, name: str, actor_user_id: str
) -> Project:
    """Create a project in the org. Duplicate NAME in the same org → error."""
    clean = (name or "").strip()
    if not clean:
        raise ConflictError("Project name is required")
    if len(clean) > 120:
        raise ConflictError("Project name must be 120 characters or fewer")

    dup = await db.execute(
        select(Project).where(
            Project.organization_id == org_id,
            Project.name == clean,
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise ConflictError(f"A project named '{clean}' already exists in this organization")

    base_slug = _slugify(clean) or "project"
    slug = base_slug
    counter = 2
    while True:
        taken = await db.execute(
            select(Project).where(
                Project.organization_id == org_id, Project.slug == slug
            )
        )
        if taken.scalar_one_or_none() is None:
            break
        slug = f"{base_slug}-{counter}"
        counter += 1

    project = Project(
        organization_id=org_id,
        name=clean,
        slug=slug,
        status="active",
        created_by=actor_user_id,
    )
    db.add(project)
    await db.commit()
    logger.info("project %s (%s) created in org %s by %s", project.id, slug, org_id, actor_user_id)
    return project


async def list_projects(db: AsyncSession, *, org_id: str) -> list[Project]:
    """Active projects of one org, creation order (RLS scopes the session)."""
    result = await db.execute(
        select(Project)
        .where(Project.organization_id == org_id, Project.status == "active")
        .order_by(Project.created_at.asc())
    )
    return list(result.scalars().all())


async def get_project_by_slug(
    db: AsyncSession, *, org_id: str, slug: str
) -> Project:
    """Resolve a gateway URL slug. Archived/missing → NotFoundError (404)."""
    result = await db.execute(
        select(Project).where(
            Project.organization_id == org_id,
            Project.slug == slug,
            Project.status == "active",
        )
    )
    project = result.scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project", slug)
    return project


async def archive_project(
    db: AsyncSession, *, project_id: str, org_id: str, actor_user_id: str
) -> Project:
    """Soft-delete: status='archived'. Gateway 404s; the slot in the
    switcher disappears; stamped history keeps its project_id."""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id, Project.organization_id == org_id
        )
    )
    project = result.scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project", project_id)
    project.status = "archived"
    await db.commit()
    logger.info("project %s archived by %s", project_id, actor_user_id)
    return project


async def ensure_default_project(
    db: AsyncSession, *, org_id: str, actor_user_id: str
) -> Project:
    """Return the org's oldest active project, creating a 'General' one when
    the org has none (auto-provision on first use)."""
    existing = await list_projects(db, org_id=org_id)
    if existing:
        return existing[0]
    return await create_project(
        db, org_id=org_id, name="General", actor_user_id=actor_user_id
    )
