"""empty message

Revision ID: 6f4584d0f392
Revises: 28f41700b9d7
Create Date: 2022-02-01 11:15:58.694290

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6f4584d0f392'
down_revision = '28f41700b9d7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user_stats', sa.Column('alert_max', sa.Float(), nullable=True))
    op.add_column('user_stats', sa.Column('alert_min', sa.Float(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user_stats', 'alert_min')
    op.drop_column('user_stats', 'alert_max')
    # ### end Alembic commands ###
