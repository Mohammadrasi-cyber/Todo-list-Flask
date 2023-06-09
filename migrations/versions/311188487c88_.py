"""empty message

Revision ID: 311188487c88
Revises: 
Create Date: 2023-06-07 15:27:33.568958

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '311188487c88'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('passwordhash', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('user_token',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(length=128), nullable=True),
    sa.Column('user', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_token')
    op.drop_table('user')
    # ### end Alembic commands ###
